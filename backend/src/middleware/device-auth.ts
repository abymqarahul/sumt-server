import type { FastifyReply, FastifyRequest } from 'fastify';
import { canonicalRequest, parseDevicePublicKey, sha256Hex, verifyDeviceSignature } from '../security/crypto.js';
import { unauthorized } from '../utils/errors.js';
import { consumeNonce } from '../services/nonce.service.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;

function header(req: FastifyRequest, name: string): string | undefined {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Authenticates a request signed by the installation's Android Keystore key.
 * Headers: X-SUMT-Installation, X-SUMT-Timestamp (ms), X-SUMT-Nonce, X-SUMT-Signature (base64 DER).
 * Signed string: canonicalRequest(method, url, timestamp, nonce, sha256(rawBody)).
 */
export async function deviceAuth(req: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const { env, prisma } = req.server.ctx;
  const installationId = header(req, 'x-sumt-installation');
  const timestamp = header(req, 'x-sumt-timestamp');
  const nonce = header(req, 'x-sumt-nonce');
  const signature = header(req, 'x-sumt-signature');

  if (!installationId || !timestamp || !nonce || !signature) {
    throw unauthorized('SIGNATURE_REQUIRED', 'Signed device request headers are missing');
  }
  if (!UUID_RE.test(installationId)) throw unauthorized('INVALID_INSTALLATION', 'Invalid installation identifier');
  if (!NONCE_RE.test(nonce)) throw unauthorized('INVALID_NONCE', 'Invalid nonce');
  const ts = Number(timestamp);
  if (!Number.isSafeInteger(ts) || Math.abs(Date.now() - ts) > env.REQUEST_CLOCK_SKEW_SEC * 1000) {
    throw unauthorized('CLOCK_SKEW', 'Request timestamp is outside the allowed window. Check the phone date and time.');
  }

  const installation = await prisma.installation.findUnique({ where: { id: installationId } });
  if (!installation) throw unauthorized('INSTALLATION_NOT_FOUND', 'Installation is not registered');

  const bodyHash = sha256Hex(req.rawBody ?? '');
  const message = canonicalRequest(req.method, req.url, timestamp, nonce, bodyHash);
  const { keyObject } = parseDevicePublicKey(installation.publicKey);
  if (!verifyDeviceSignature(keyObject, message, signature)) {
    throw unauthorized('INVALID_SIGNATURE', 'Device signature verification failed');
  }

  await consumeNonce(prisma, nonce, installation.id, env.REQUEST_CLOCK_SKEW_SEC * 2);
  req.installation = installation;
}
