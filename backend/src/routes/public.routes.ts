import type { FastifyInstance } from 'fastify';
import { parseDevicePublicKey, registrationMessage, verifyDeviceSignature, verifyTicket } from '../security/crypto.js';
import { registerSchema } from '../validators/schemas.js';
import { registerInstallation } from '../services/installation.service.js';
import { buildLicenseView, getActiveLicense, effectiveStatus } from '../services/license.service.js';
import { badRequest, forbidden, notFound, unauthorized } from '../utils/errors.js';
import { parseRange } from '../services/resource.service.js';
import crypto from 'node:crypto';

export interface TicketPayload {
  rid: string;
  iid: string;
  exp: number;
}

export async function publicRoutes(app: FastifyInstance) {
  const ctx = app.ctx;

  app.get('/health', async (_req, reply) => {
    let db = 'ok';
    try {
      await ctx.prisma.$queryRaw`SELECT 1`;
    } catch {
      db = 'error';
    }
    const body = { status: db === 'ok' ? 'ok' : 'degraded', db, version: process.env.npm_package_version ?? '1.0.0', time: new Date().toISOString() };
    return reply.code(db === 'ok' ? 200 : 503).send(body);
  });

  /** Licence-token verification key (public). The Android app also embeds it at build time. */
  app.get('/public-key', async () => ({ alg: 'ES256', format: 'spki-der-base64', publicKey: ctx.signer.publicKeySpkiBase64 }));

  app.post(
    '/installations/register',
    { config: { rateLimit: { max: ctx.env.RATE_LIMIT_REGISTER_PER_MIN, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const body = registerSchema.parse(req.body);
      const ts = Number(body.timestamp);
      if (Math.abs(Date.now() - ts) > ctx.env.REQUEST_CLOCK_SKEW_SEC * 1000) {
        throw unauthorized('CLOCK_SKEW', 'Phone date/time is incorrect. Enable automatic date & time.');
      }
      let key;
      try {
        key = parseDevicePublicKey(body.publicKey);
      } catch (e) {
        throw badRequest('INVALID_PUBLIC_KEY', (e as Error).message);
      }
      // Proof of possession: the caller must hold the private key.
      if (!verifyDeviceSignature(key.keyObject, registrationMessage(body.publicKey, body.timestamp, body.nonce), body.signature)) {
        throw unauthorized('INVALID_SIGNATURE', 'Registration signature verification failed');
      }

      const expectedNonce = crypto.createHash('sha256').update(Buffer.from(key.spkiBase64, 'base64')).digest('base64url');
      const integrity = await ctx.integrity.verify(body.integrityToken, expectedNonce);
      if (ctx.integrity.mode === 'enforce' && !integrity.passed) {
        throw forbidden('INTEGRITY_FAILED', 'This device did not pass the integrity check');
      }

      const { installation, created } = await registerInstallation(
        ctx.prisma,
        key,
        body.device,
        req.ip,
        integrity.checked ? integrity.summary : null,
      );
      const license = await getActiveLicense(ctx.prisma, installation.id);
      return reply.code(created ? 201 : 200).send({ created, ...buildLicenseView(ctx, installation, license) });
    },
  );

  /** Ticketed download (no headers needed — usable by OkHttp or DownloadManager). Supports Range resume. */
  app.get<{ Params: { ticket: string } }>('/resources/download/:ticket', async (req, reply) => {
    const t = verifyTicket<TicketPayload>(req.params.ticket, ctx.env.DOWNLOAD_TICKET_SECRET);
    if (!t || typeof t.exp !== 'number' || t.exp * 1000 < Date.now()) throw unauthorized('INVALID_TICKET', 'Download link is invalid or expired');

    const [resource, installation] = await Promise.all([
      ctx.prisma.resource.findUnique({ where: { id: t.rid } }),
      ctx.prisma.installation.findUnique({ where: { id: t.iid } }),
    ]);
    if (!resource || !resource.published) throw notFound('RESOURCE_NOT_FOUND', 'Resource is not available');
    if (!installation) throw unauthorized('INVALID_TICKET', 'Download link is invalid');
    const license = await getActiveLicense(ctx.prisma, installation.id);
    if (effectiveStatus(installation, license) !== 'ACTIVE') throw forbidden('LICENSE_REQUIRED', 'An active licence is required');

    const stat = await ctx.storage.stat(resource.storageKey);
    if (!stat) throw notFound('FILE_MISSING', 'Resource file is missing on the server');

    const range = parseRange(req.headers.range, stat.size);
    reply.header('Accept-Ranges', 'bytes');
    reply.header('X-SUMT-SHA256', resource.sha256);
    reply.header('Content-Type', resource.mimeType);
    reply.header('Content-Disposition', `attachment; filename="${resource.fileName}"`);
    reply.header('Cache-Control', 'private, no-store');
    if (range === null) {
      reply.header('Content-Range', `bytes */${stat.size}`);
      return reply.code(416).send();
    }
    if (range) {
      reply.code(206);
      reply.header('Content-Range', `bytes ${range.start}-${range.end}/${stat.size}`);
      reply.header('Content-Length', range.end - range.start + 1);
      return reply.send(ctx.storage.createReadStream(resource.storageKey, range));
    }
    reply.header('Content-Length', stat.size);
    return reply.send(ctx.storage.createReadStream(resource.storageKey));
  });
}
