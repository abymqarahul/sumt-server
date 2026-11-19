import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  generateActivationKey,
  hashActivationKey,
  LicenseSigner,
  normalizeActivationKey,
  parseDevicePublicKey,
  signTicket,
  verifyDeviceSignature,
  verifyTicket,
} from '../src/security/crypto.js';
import { parseRange, safeFileName } from '../src/services/resource.service.js';
import { validatePasswordStrength } from '../src/services/admin-auth.service.js';
import { loadEnv } from '../src/config/env.js';

describe('activation keys', () => {
  it('have the SUMT-XXXX-XXXX-XXXX-XXXX format and are unique', () => {
    const set = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const k = generateActivationKey();
      expect(k).toMatch(/^SUMT-[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
      set.add(k);
    }
    expect(set.size).toBe(2000);
  });

  it('normalise case, spacing and look-alike characters', () => {
    const k = generateActivationKey();
    const n = normalizeActivationKey(k)!;
    expect(normalizeActivationKey(k.toLowerCase().replace(/-/g, ' '))).toBe(n);
    expect(normalizeActivationKey(k.replace('SUMT-', ''))).toBe(n);
    expect(normalizeActivationKey('SUMT-OOOO-IIII-LLLL-0000')).toBe('0000111111110000');
    expect(normalizeActivationKey('SUMT-UUUU-0000-0000-0000')).toBeNull();
    expect(normalizeActivationKey('too-short')).toBeNull();
  });

  it('hash depends on the pepper', () => {
    expect(hashActivationKey('A'.repeat(16), 'p'.repeat(32))).not.toBe(hashActivationKey('A'.repeat(16), 'q'.repeat(32)));
  });
});

describe('device keys', () => {
  it('accepts EC P-256 SPKI and verifies DER signatures', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const spki = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const parsed = parseDevicePublicKey(spki);
    expect(parsed.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    const sig = crypto.sign('sha256', Buffer.from('hello'), { key: privateKey, dsaEncoding: 'der' }).toString('base64');
    expect(verifyDeviceSignature(parsed.keyObject, 'hello', sig)).toBe(true);
    expect(verifyDeviceSignature(parsed.keyObject, 'hellO', sig)).toBe(false);
    expect(verifyDeviceSignature(parsed.keyObject, 'hello', 'garbage')).toBe(false);
  });

  it('rejects other curves and RSA keys', () => {
    const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    expect(() => parseDevicePublicKey(p384)).toThrow();
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    expect(() => parseDevicePublicKey(rsa)).toThrow();
  });
});

describe('licence tokens', () => {
  it('round-trip and detect tampering', () => {
    const pk = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
    const s = new LicenseSigner(pk);
    const tok = s.sign({ v: 1, iid: 'i', did: 'SUMT-1', kfp: 'f', st: 'ACTIVE', lid: 'l', plan: 'STANDARD', iat: 1, exp: null, gu: 2 });
    expect(s.verify(tok)?.did).toBe('SUMT-1');
    const parts = tok.split('.');
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(parts[1]!, 'base64url').toString()), exp: 9e12 })).toString('base64url');
    expect(s.verify(`v1.${forged}.${parts[2]}`)).toBeNull();
    // Verifiable with only the public key (what the Android app does).
    const pub = crypto.createPublicKey({ key: Buffer.from(s.publicKeySpkiBase64, 'base64'), format: 'der', type: 'spki' });
    expect(crypto.verify('sha256', Buffer.from(`v1.${parts[1]}`), { key: pub, dsaEncoding: 'der' }, Buffer.from(parts[2]!, 'base64url'))).toBe(true);
  });
});

describe('download tickets', () => {
  it('reject modified payloads and wrong secrets', () => {
    const secret = 'x'.repeat(40);
    const t = signTicket({ rid: 'a', iid: 'b', exp: 1 }, secret);
    expect(verifyTicket<{ rid: string }>(t, secret)?.rid).toBe('a');
    expect(verifyTicket(t, 'y'.repeat(40))).toBeNull();
    const [, mac] = t.split('.');
    const other = Buffer.from(JSON.stringify({ rid: 'z', iid: 'b', exp: 1 })).toString('base64url');
    expect(verifyTicket(`${other}.${mac}`, secret)).toBeNull();
  });
});

describe('helpers', () => {
  it('parse byte ranges', () => {
    expect(parseRange(undefined, 100)).toBeUndefined();
    expect(parseRange('bytes=0-9', 100)).toEqual({ start: 0, end: 9 });
    expect(parseRange('bytes=90-', 100)).toEqual({ start: 90, end: 99 });
    expect(parseRange('bytes=-10', 100)).toEqual({ start: 90, end: 99 });
    expect(parseRange('bytes=100-', 100)).toBeNull();
    expect(parseRange('bytes=5-1', 100)).toBeNull();
    expect(parseRange('items=0-1', 100)).toBeNull();
  });

  it('sanitise file names', () => {
    expect(safeFileName('../../etc/passwd')).toBe('passwd');
    expect(safeFileName('C:\\fw\\my file (1).bin')).toBe('my_file__1_.bin');
  });

  it('enforce password strength', () => {
    expect(validatePasswordStrength('short')).not.toBeNull();
    expect(validatePasswordStrength('alllowercaseletters')).not.toBeNull();
    expect(validatePasswordStrength('Str0ng!Passw0rd')).toBeNull();
  });

  it('refuse to start with missing secrets', () => {
    expect(() => loadEnv({ DATABASE_URL: 'postgres://x' })).toThrow(/LICENSE_SIGNING_PRIVATE_KEY/);
  });
});
