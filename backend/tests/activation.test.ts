import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { adminLogin, bearer, cleanDb, createAdmin, makeApp, prisma, TestDevice } from './helpers.js';

let app: FastifyInstance;
let token: string;

async function generate(installationId: string, body: Record<string, unknown> = {}) {
  const res = await app.inject({
    method: 'POST',
    url: '/api/v1/admin/activations/generate',
    headers: bearer(token),
    payload: { installationId, ...body },
  });
  expect(res.statusCode, res.body).toBe(200);
  return res.json() as { activationKey: string; keyId: string; expiresAt: string };
}

beforeAll(async () => {
  app = await makeApp({ ACTIVATION_MAX_FAILURES: '5' });
});
afterAll(async () => {
  await app.close();
  await prisma.$disconnect();
});
beforeEach(async () => {
  await cleanDb();
  await createAdmin('SUPERADMIN', 'owner@sumt.test');
  token = (await adminLogin(app, 'owner@sumt.test')).accessToken;
});

describe('health', () => {
  it('reports ok with database connectivity', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ status: 'ok', db: 'ok' });
  });
});

describe('installation registration', () => {
  it('assigns sequential SUMT IDs starting at 10001 and starts PENDING', async () => {
    const a = new TestDevice(app);
    const b = new TestDevice(app);
    const ra = await a.register();
    const rb = await b.register();
    expect(ra.statusCode).toBe(201);
    expect(ra.json()).toMatchObject({ displayId: 'SUMT-10001', status: 'PENDING', licenseToken: null, created: true });
    expect(rb.json().displayId).toBe('SUMT-10002');
  });

  it('is idempotent for the same Keystore key', async () => {
    const a = new TestDevice(app);
    await a.register();
    const again = await a.register();
    expect(again.statusCode).toBe(200);
    expect(again.json()).toMatchObject({ displayId: 'SUMT-10001', created: false });
    expect(await prisma.installation.count()).toBe(1);
  });

  it('handles concurrent first-launch registration without duplicates', async () => {
    const a = new TestDevice(app);
    const results = await Promise.all(Array.from({ length: 8 }, () => a.register()));
    expect(results.every((r) => r.statusCode < 300)).toBe(true);
    expect(new Set(results.map((r) => r.json().installationId)).size).toBe(1);
    expect(await prisma.installation.count()).toBe(1);
  });

  it('rejects a registration without proof of key possession', async () => {
    const a = new TestDevice(app);
    const other = new TestDevice(app);
    const ts = String(Date.now());
    const nonce = crypto.randomBytes(16).toString('base64url');
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/installations/register',
      payload: { publicKey: a.spki, timestamp: ts, nonce, signature: other.sign(`SUMT-register-v1\n${a.spki}\n${ts}\n${nonce}`) },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('INVALID_SIGNATURE');
  });

  it('rejects a wrong clock and invalid keys', async () => {
    const a = new TestDevice(app);
    a.clockOffsetMs = -3600_000;
    expect((await a.register()).json().error).toBe('CLOCK_SKEW');
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/installations/register',
      payload: { publicKey: Buffer.alloc(91, 1).toString('base64'), timestamp: String(Date.now()), nonce: 'a'.repeat(22), signature: 'AAAAAAAAAAAA' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('INVALID_PUBLIC_KEY');
  });
});

describe('signed device requests', () => {
  it('require headers, a valid signature and a fresh nonce', async () => {
    const a = new TestDevice(app);
    await a.register();
    expect((await app.inject({ method: 'GET', url: '/api/v1/licenses/verify' })).json().error).toBe('SIGNATURE_REQUIRED');

    const headers = a.signedHeaders('GET', '/api/v1/licenses/verify');
    expect((await app.inject({ method: 'GET', url: '/api/v1/licenses/verify', headers })).statusCode).toBe(200);
    const replay = await app.inject({ method: 'GET', url: '/api/v1/licenses/verify', headers });
    expect(replay.statusCode).toBe(401);
    expect(replay.json().error).toBe('REPLAY_DETECTED');

    const forged = { ...a.signedHeaders('GET', '/api/v1/licenses/verify'), 'x-sumt-signature': new TestDevice(app).sign('x') };
    expect((await app.inject({ method: 'GET', url: '/api/v1/licenses/verify', headers: forged })).json().error).toBe('INVALID_SIGNATURE');
  });

  it('bind the signature to the body (tampering fails)', async () => {
    const a = new TestDevice(app);
    await a.register();
    const body = JSON.stringify({ activationKey: 'SUMT-AAAA-AAAA-AAAA-AAAA' });
    const headers = a.signedHeaders('POST', '/api/v1/activations/consume', body);
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/activations/consume',
      headers: { ...headers, 'content-type': 'application/json' },
      payload: JSON.stringify({ activationKey: 'SUMT-BBBB-BBBB-BBBB-BBBB' }),
    });
    expect(res.json().error).toBe('INVALID_SIGNATURE');
  });

  it('reject an installation impersonated by another key', async () => {
    const a = new TestDevice(app);
    const b = new TestDevice(app);
    await a.register();
    await b.register();
    b.installationId = a.installationId; // B claims to be A
    expect((await b.verify()).json().error).toBe('INVALID_SIGNATURE');
  });
});

describe('activation lifecycle', () => {
  it('generate → consume → ACTIVE with a device-bound licence token', async () => {
    const a = new TestDevice(app);
    await a.register();
    const { activationKey } = await generate(a.displayId, { licenseDays: 365 });
    expect(activationKey).toMatch(/^SUMT-/);

    const stored = await prisma.activationKey.findFirstOrThrow();
    expect(stored.keyHash).not.toContain(activationKey.replace(/-/g, ''));
    expect(JSON.stringify(stored)).not.toContain(activationKey);

    const res = await a.consume(activationKey);
    expect(res.statusCode, res.body).toBe(200);
    const body = res.json();
    expect(body.status).toBe('ACTIVE');
    expect(new Date(body.expiresAt).getTime()).toBeGreaterThan(Date.now() + 364 * 86400_000);

    const payload = JSON.parse(Buffer.from(body.licenseToken.split('.')[1], 'base64url').toString());
    const fp = crypto.createHash('sha256').update(Buffer.from(a.spki, 'base64')).digest('hex');
    expect(payload).toMatchObject({ did: a.displayId, kfp: fp, st: 'ACTIVE' });
    expect(app.ctx.signer.verify(body.licenseToken)).not.toBeNull();

    const v = await a.verify();
    expect(v.json().status).toBe('ACTIVE');
    const actions = (await prisma.auditLog.findMany()).map((l) => l.action);
    expect(actions).toEqual(expect.arrayContaining(['installation.register', 'activation_key.generate', 'activation_key.consume']));
  });

  it('accepts the key typed in lowercase with spaces', async () => {
    const a = new TestDevice(app);
    await a.register();
    const { activationKey } = await generate(a.displayId);
    expect((await a.consume(activationKey.toLowerCase().replace(/-/g, ' '))).json().status).toBe('ACTIVE');
  });

  it('a key works only once', async () => {
    const a = new TestDevice(app);
    await a.register();
    const { activationKey } = await generate(a.displayId);
    expect((await a.consume(activationKey)).statusCode).toBe(200);
    const again = await a.consume(activationKey);
    expect(again.statusCode).toBe(409);
    expect(again.json().error).toBe('KEY_ALREADY_USED');
  });

  it('only one of many simultaneous consume requests succeeds', async () => {
    const a = new TestDevice(app);
    await a.register();
    const { activationKey } = await generate(a.displayId);
    const results = await Promise.all(Array.from({ length: 12 }, () => a.consume(activationKey)));
    expect(results.filter((r) => r.statusCode === 200)).toHaveLength(1);
    expect(results.filter((r) => r.json().error === 'KEY_ALREADY_USED')).toHaveLength(11);
    expect(await prisma.license.count()).toBe(1);
  });

  it('anti-sharing: a copied APK gets its own ID and cannot use the original key', async () => {
    const original = new TestDevice(app, 'Customer phone');
    const copy = new TestDevice(app, 'Friend phone');
    await original.register();
    await copy.register();
    expect(copy.displayId).not.toBe(original.displayId);
    const { activationKey } = await generate(original.displayId);

    const stolen = await copy.consume(activationKey);
    expect(stolen.statusCode).toBe(400);
    expect(stolen.json().error).toBe('INVALID_KEY');
    expect((await copy.verify()).json().status).toBe('PENDING');

    expect((await original.consume(activationKey)).json().status).toBe('ACTIVE');
    // After use it never works again, for anyone.
    expect((await copy.consume(activationKey)).json().error).toBe('INVALID_KEY');
    expect((await copy.verify()).json().status).toBe('PENDING');
  });

  it('rejects expired keys', async () => {
    const a = new TestDevice(app);
    await a.register();
    const { activationKey, keyId } = await generate(a.displayId, { keyValidHours: 1 });
    await prisma.activationKey.update({ where: { id: keyId }, data: { expiresAt: new Date(Date.now() - 1000) } });
    const res = await a.consume(activationKey);
    expect(res.json().error).toBe('KEY_EXPIRED');
  });

  it('a newly generated key supersedes the previous unused one', async () => {
    const a = new TestDevice(app);
    await a.register();
    const first = await generate(a.displayId);
    const second = await generate(a.displayId);
    expect((await a.consume(first.activationKey)).json().error).toBe('KEY_REVOKED');
    expect((await a.consume(second.activationKey)).json().status).toBe('ACTIVE');
  });

  it('locks activation after repeated failures (brute-force protection)', async () => {
    const a = new TestDevice(app);
    await a.register();
    for (let i = 0; i < 5; i++) {
      expect((await a.consume('SUMT-0000-0000-0000-000' + i)).json().error).toBe('INVALID_KEY');
    }
    const { activationKey } = await generate(a.displayId);
    const res = await a.consume(activationKey);
    expect(res.statusCode).toBe(423);
    expect(res.json().error).toBe('ACTIVATION_LOCKED');
    // Owner reset clears the lock.
    await app.inject({ method: 'POST', url: `/api/v1/admin/installations/${a.displayId}/reset`, headers: bearer(token), payload: {} });
    const k2 = await generate(a.displayId);
    expect((await a.consume(k2.activationKey)).json().status).toBe('ACTIVE');
  });

  it('renewal extends from the current expiry', async () => {
    const a = new TestDevice(app);
    await a.register();
    const k1 = await generate(a.displayId, { licenseDays: 30 });
    const first = (await a.consume(k1.activationKey)).json();
    const k2 = await generate(a.displayId, { licenseDays: 30 });
    const second = (await a.consume(k2.activationKey)).json();
    const diff = new Date(second.expiresAt).getTime() - new Date(first.expiresAt).getTime();
    expect(Math.round(diff / 86400_000)).toBe(30);
    expect(await prisma.license.count({ where: { status: 'ACTIVE' } })).toBe(1);
  });

  it('lifetime keys produce a licence without expiry', async () => {
    const a = new TestDevice(app);
    await a.register();
    const { activationKey } = await generate(a.displayId, { licenseDays: null });
    const body = (await a.consume(activationKey)).json();
    expect(body.expiresAt).toBeNull();
    expect(body.offlineGraceUntil).not.toBeNull();
  });
});

describe('licence management', () => {
  async function activated() {
    const a = new TestDevice(app);
    await a.register();
    const { activationKey } = await generate(a.displayId, { licenseDays: 365 });
    await a.consume(activationKey);
    const lic = await prisma.license.findFirstOrThrow({ where: { installationId: a.installationId, status: 'ACTIVE' } });
    return { a, lic };
  }

  it('revocation takes effect on the next verify', async () => {
    const { a, lic } = await activated();
    const res = await app.inject({ method: 'POST', url: `/api/v1/admin/licenses/${lic.id}/revoke`, headers: bearer(token), payload: { reason: 'refund' } });
    expect(res.statusCode).toBe(200);
    const v = (await a.verify()).json();
    expect(v.status).toBe('REVOKED');
    expect(v.licenseToken).toBeNull();
  });

  it('expiry: an expired licence reports EXPIRED and can be extended', async () => {
    const { a, lic } = await activated();
    const past = new Date(Date.now() - 60_000).toISOString();
    await app.inject({ method: 'PATCH', url: `/api/v1/admin/licenses/${lic.id}`, headers: bearer(token), payload: { expiresAt: past } });
    expect((await a.verify()).json().status).toBe('EXPIRED');
    expect((await a.request('GET', '/api/v1/resources')).statusCode).toBe(403);

    const list = await app.inject({ method: 'GET', url: '/api/v1/admin/installations?status=EXPIRED', headers: bearer(token) });
    expect(list.json().total).toBe(1);

    await app.inject({ method: 'PATCH', url: `/api/v1/admin/licenses/${lic.id}`, headers: bearer(token), payload: { expiresAt: null } });
    expect((await a.verify()).json()).toMatchObject({ status: 'ACTIVE', expiresAt: null });
  });

  it('block / unblock', async () => {
    const { a } = await activated();
    const blk = await app.inject({ method: 'POST', url: `/api/v1/admin/installations/${a.displayId}/block`, headers: bearer(token), payload: { reason: 'shared' } });
    expect(blk.json().effectiveStatus).toBe('BLOCKED');
    expect((await a.verify()).json().status).toBe('BLOCKED');
    const gen = await app.inject({ method: 'POST', url: '/api/v1/admin/activations/generate', headers: bearer(token), payload: { installationId: a.displayId } });
    expect(gen.json().error).toBe('INSTALLATION_BLOCKED');
    await app.inject({ method: 'POST', url: `/api/v1/admin/installations/${a.displayId}/unblock`, headers: bearer(token) });
    expect((await a.verify()).json().status).toBe('ACTIVE');
  });

  it('reset returns the installation to PENDING', async () => {
    const { a } = await activated();
    const res = await app.inject({ method: 'POST', url: `/api/v1/admin/installations/${a.installationId}/reset`, headers: bearer(token), payload: {} });
    expect(res.json().status).toBe('PENDING');
    expect((await a.verify()).json().status).toBe('PENDING');
  });

  it('transfer moves the remaining licence to a reinstalled device', async () => {
    const { a, lic } = await activated();
    const reinstall = new TestDevice(app);
    await reinstall.register();
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/admin/installations/${a.displayId}/transfer`,
      headers: bearer(token),
      payload: { toInstallationId: reinstall.displayId },
    });
    expect(res.statusCode, res.body).toBe(200);
    expect((await a.verify()).json().status).toBe('REVOKED');
    const v = (await reinstall.verify()).json();
    expect(v.status).toBe('ACTIVE');
    expect(v.expiresAt).toBe(lic.expiresAt!.toISOString());
  });
});

describe('admin views', () => {
  it('dashboard counts, search and installation details', async () => {
    const a = new TestDevice(app, 'Redmi Note');
    const b = new TestDevice(app);
    await a.register();
    await b.register();
    const { activationKey } = await generate(a.displayId);
    await a.consume(activationKey);

    const d = (await app.inject({ method: 'GET', url: '/api/v1/admin/dashboard', headers: bearer(token) })).json();
    expect(d).toMatchObject({ totalInstallations: 2, pending: 1, active: 1, blocked: 0 });

    const s1 = (await app.inject({ method: 'GET', url: '/api/v1/admin/installations?q=10001', headers: bearer(token) })).json();
    expect(s1.items.map((i: { displayId: string }) => i.displayId)).toEqual(['SUMT-10001']);
    const s2 = (await app.inject({ method: 'GET', url: '/api/v1/admin/installations?q=redmi', headers: bearer(token) })).json();
    expect(s2.total).toBe(1);
    const pend = (await app.inject({ method: 'GET', url: '/api/v1/admin/installations?status=PENDING', headers: bearer(token) })).json();
    expect(pend.items[0].displayId).toBe(b.displayId);

    const det = (await app.inject({ method: 'GET', url: `/api/v1/admin/installations/sumt-10001`, headers: bearer(token) })).json();
    expect(det.activationKeys[0].state).toBe('USED');
    expect(det.activationKeys[0]).not.toHaveProperty('keyHash');
    expect(det.history.length).toBeGreaterThan(0);

    const hist = (await app.inject({ method: 'GET', url: `/api/v1/admin/activations/history?installationId=${a.displayId}`, headers: bearer(token) })).json();
    expect(hist.total).toBe(1);

    const logs = (await app.inject({ method: 'GET', url: '/api/v1/admin/audit-logs?action=activation_key', headers: bearer(token) })).json();
    expect(logs.total).toBe(2);
  });
});
