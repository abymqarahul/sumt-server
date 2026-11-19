import crypto from 'node:crypto';

// Crockford base32 (no I, L, O, U) — unambiguous when read over the phone.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function sha256Hex(data: crypto.BinaryLike): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** 80-bit random activation key formatted SUMT-XXXX-XXXX-XXXX-XXXX. */
export function generateActivationKey(): string {
  const bytes = crypto.randomBytes(10); // 80 bits → 16 base32 chars
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return `SUMT-${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8, 12)}-${out.slice(12, 16)}`;
}

/** Normalises user input: case, spaces, dashes and common look-alikes. */
export function normalizeActivationKey(input: string): string | null {
  let s = input.toUpperCase().replace(/[\s-]/g, '');
  if (s.startsWith('SUMT')) s = s.slice(4);
  s = s.replace(/O/g, '0').replace(/[IL]/g, '1');
  if (!/^[0-9A-HJKMNP-TV-Z]{16}$/.test(s)) return null;
  return s;
}

export function hashActivationKey(normalized: string, pepper: string): string {
  return crypto.createHmac('sha256', pepper).update(`sumt-activation:${normalized}`).digest('hex');
}

export interface ParsedPublicKey {
  keyObject: crypto.KeyObject;
  spkiBase64: string;
  fingerprint: string;
}

/** Accepts an EC P-256 SubjectPublicKeyInfo (DER, base64) as produced by Android Keystore. */
export function parseDevicePublicKey(spkiBase64: string): ParsedPublicKey {
  const der = Buffer.from(spkiBase64, 'base64');
  if (der.length < 60 || der.length > 200) throw new Error('Public key has unexpected length');
  const keyObject = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  const details = keyObject.asymmetricKeyDetails;
  if (keyObject.asymmetricKeyType !== 'ec' || details?.namedCurve !== 'prime256v1') {
    throw new Error('Only EC P-256 public keys are accepted');
  }
  const canonical = keyObject.export({ format: 'der', type: 'spki' });
  return { keyObject, spkiBase64: canonical.toString('base64'), fingerprint: sha256Hex(canonical) };
}

/** Verifies an ECDSA-SHA256 signature in DER encoding (Android `SHA256withECDSA`). */
export function verifyDeviceSignature(key: crypto.KeyObject, message: string, signatureB64: string): boolean {
  try {
    const sig = Buffer.from(signatureB64, 'base64');
    if (sig.length < 8 || sig.length > 80) return false;
    return crypto.verify('sha256', Buffer.from(message, 'utf8'), { key, dsaEncoding: 'der' }, sig);
  } catch {
    return false;
  }
}

export function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/** Canonical string a device signs for authenticated requests. */
export function canonicalRequest(method: string, pathWithQuery: string, timestamp: string, nonce: string, bodySha256: string) {
  return ['SUMT-v1', method.toUpperCase(), pathWithQuery, timestamp, nonce, bodySha256].join('\n');
}

export function registrationMessage(spkiBase64: string, timestamp: string, nonce: string) {
  return ['SUMT-register-v1', spkiBase64, timestamp, nonce].join('\n');
}

// ---------- Licence tokens (ES256, DER signature, compact "v1.<payload>.<sig>") ----------

export interface LicenseTokenPayload {
  v: 1;
  iid: string; // installation uuid
  did: string; // display id SUMT-10001
  kfp: string; // device key fingerprint — app must compare to its own key
  st: 'ACTIVE';
  lid: string;
  plan: string;
  iat: number; // seconds
  exp: number | null; // licence expiry (seconds) or null for lifetime
  gu: number; // offline grace — app must re-verify online before this time
}

export class LicenseSigner {
  private readonly privateKey: crypto.KeyObject;
  readonly publicKeySpkiBase64: string;

  constructor(pkcs8Base64: string) {
    this.privateKey = crypto.createPrivateKey({ key: Buffer.from(pkcs8Base64, 'base64'), format: 'der', type: 'pkcs8' });
    if (this.privateKey.asymmetricKeyType !== 'ec' || this.privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
      throw new Error('LICENSE_SIGNING_PRIVATE_KEY must be an EC P-256 PKCS#8 key');
    }
    this.publicKeySpkiBase64 = crypto
      .createPublicKey(this.privateKey)
      .export({ format: 'der', type: 'spki' })
      .toString('base64');
  }

  sign(payload: LicenseTokenPayload): string {
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signingInput = `v1.${body}`;
    const sig = crypto.sign('sha256', Buffer.from(signingInput), { key: this.privateKey, dsaEncoding: 'der' });
    return `${signingInput}.${sig.toString('base64url')}`;
  }

  verify(token: string): LicenseTokenPayload | null {
    const parts = token.split('.');
    if (parts.length !== 3 || parts[0] !== 'v1') return null;
    const ok = crypto.verify(
      'sha256',
      Buffer.from(`v1.${parts[1]}`),
      { key: crypto.createPublicKey(this.privateKey), dsaEncoding: 'der' },
      Buffer.from(parts[2]!, 'base64url'),
    );
    if (!ok) return null;
    return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as LicenseTokenPayload;
  }
}

// ---------- Download tickets (HMAC) ----------

export function signTicket(payload: object, secret: string): string {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${mac}`;
}

export function verifyTicket<T>(ticket: string, secret: string): T | null {
  const [body, mac] = ticket.split('.');
  if (!body || !mac) return null;
  const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (!timingSafeEqualStr(mac, expected)) return null;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as T;
  } catch {
    return null;
  }
}
