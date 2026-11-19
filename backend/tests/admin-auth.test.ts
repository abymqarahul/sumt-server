import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { adminLogin, bearer, cleanDb, createAdmin, makeApp, prisma, TEST_PASSWORD, TestDevice } from './helpers.js';

let app: FastifyInstance;

beforeAll(async () => {
  app = await makeApp({ ADMIN_MAX_FAILED_LOGINS: '3' });
});
afterAll(async () => {
  await app.close();
  await prisma.$disconnect();
});
beforeEach(async () => {
  await cleanDb();
});

describe('admin authentication', () => {
  it('logs in with correct credentials only', async () => {
    await createAdmin('ADMIN', 'a@sumt.test');
    const ok = await app.inject({ method: 'POST', url: '/api/v1/admin/login', payload: { email: 'A@sumt.test', password: TEST_PASSWORD } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().admin).not.toHaveProperty('passwordHash');
    const bad = await app.inject({ method: 'POST', url: '/api/v1/admin/login', payload: { email: 'a@sumt.test', password: 'wrong' } });
    expect(bad.statusCode).toBe(401);
    const unknown = await app.inject({ method: 'POST', url: '/api/v1/admin/login', payload: { email: 'nobody@sumt.test', password: 'wrong' } });
    expect(unknown.json().error).toBe('INVALID_CREDENTIALS');
  });

  it('locks the account after repeated failures', async () => {
    await createAdmin('ADMIN', 'a@sumt.test');
    for (let i = 0; i < 3; i++) await app.inject({ method: 'POST', url: '/api/v1/admin/login', payload: { email: 'a@sumt.test', password: 'wrong' } });
    const res = await app.inject({ method: 'POST', url: '/api/v1/admin/login', payload: { email: 'a@sumt.test', password: TEST_PASSWORD } });
    expect(res.statusCode).toBe(423);
  });

  it('rotates refresh tokens and detects reuse', async () => {
    await createAdmin('ADMIN', 'a@sumt.test');
    const t1 = await adminLogin(app, 'a@sumt.test');
    const r1 = await app.inject({ method: 'POST', url: '/api/v1/admin/refresh', payload: { refreshToken: t1.refreshToken } });
    expect(r1.statusCode).toBe(200);
    const t2 = r1.json();
    expect(t2.refreshToken).not.toBe(t1.refreshToken);

    const reuse = await app.inject({ method: 'POST', url: '/api/v1/admin/refresh', payload: { refreshToken: t1.refreshToken } });
    expect(reuse.json().error).toBe('REFRESH_TOKEN_REUSED');
    // Reuse kills the whole family, including the newest token and access tokens.
    expect((await app.inject({ method: 'POST', url: '/api/v1/admin/refresh', payload: { refreshToken: t2.refreshToken } })).statusCode).toBe(401);
    expect((await app.inject({ method: 'GET', url: '/api/v1/admin/me', headers: bearer(t2.accessToken) })).statusCode).toBe(401);
  });

  it('logout revokes the refresh token', async () => {
    await createAdmin('ADMIN', 'a@sumt.test');
    const t = await adminLogin(app, 'a@sumt.test');
    await app.inject({ method: 'POST', url: '/api/v1/admin/logout', payload: { refreshToken: t.refreshToken } });
    expect((await app.inject({ method: 'POST', url: '/api/v1/admin/refresh', payload: { refreshToken: t.refreshToken } })).statusCode).toBe(401);
  });
});

describe('admin authorisation is enforced by the server', () => {
  it('rejects missing, forged and device credentials', async () => {
    expect((await app.inject({ method: 'GET', url: '/api/v1/admin/installations' })).statusCode).toBe(401);
    expect((await app.inject({ method: 'GET', url: '/api/v1/admin/installations', headers: bearer('eyJhbGciOiJub25lIn0.e30.') })).statusCode).toBe(401);
    const d = new TestDevice(app);
    await d.register();
    const res = await app.inject({ method: 'GET', url: '/api/v1/admin/installations', headers: d.signedHeaders('GET', '/api/v1/admin/installations') });
    expect(res.statusCode).toBe(401);
  });

  it('VIEWER can read but not generate keys or block', async () => {
    await createAdmin('VIEWER', 'v@sumt.test');
    const { accessToken } = await adminLogin(app, 'v@sumt.test');
    const d = new TestDevice(app);
    await d.register();
    expect((await app.inject({ method: 'GET', url: '/api/v1/admin/installations', headers: bearer(accessToken) })).statusCode).toBe(200);
    const gen = await app.inject({ method: 'POST', url: '/api/v1/admin/activations/generate', headers: bearer(accessToken), payload: { installationId: d.displayId } });
    expect(gen.statusCode).toBe(403);
    const blk = await app.inject({ method: 'POST', url: `/api/v1/admin/installations/${d.displayId}/block`, headers: bearer(accessToken), payload: {} });
    expect(blk.statusCode).toBe(403);
  });

  it('only SUPERADMIN manages admins; disabling an admin kills their session', async () => {
    await createAdmin('SUPERADMIN', 's@sumt.test');
    await createAdmin('ADMIN', 'a@sumt.test');
    const s = await adminLogin(app, 's@sumt.test');
    const a = await adminLogin(app, 'a@sumt.test');
    expect((await app.inject({ method: 'GET', url: '/api/v1/admin/admins', headers: bearer(a.accessToken) })).statusCode).toBe(403);

    const weak = await app.inject({ method: 'POST', url: '/api/v1/admin/admins', headers: bearer(s.accessToken), payload: { email: 'n@sumt.test', password: 'weakweakweak', role: 'ADMIN' } });
    expect(weak.json().error).toBe('WEAK_PASSWORD');
    const created = await app.inject({ method: 'POST', url: '/api/v1/admin/admins', headers: bearer(s.accessToken), payload: { email: 'n@sumt.test', password: TEST_PASSWORD, role: 'VIEWER' } });
    expect(created.statusCode).toBe(201);

    const aId = (await prisma.admin.findUniqueOrThrow({ where: { email: 'a@sumt.test' } })).id;
    await app.inject({ method: 'PATCH', url: `/api/v1/admin/admins/${aId}`, headers: bearer(s.accessToken), payload: { disabled: true } });
    expect((await app.inject({ method: 'GET', url: '/api/v1/admin/me', headers: bearer(a.accessToken) })).statusCode).toBe(401);

    const sId = (await prisma.admin.findUniqueOrThrow({ where: { email: 's@sumt.test' } })).id;
    const self = await app.inject({ method: 'PATCH', url: `/api/v1/admin/admins/${sId}`, headers: bearer(s.accessToken), payload: { disabled: true } });
    expect(self.json().error).toBe('SELF_LOCKOUT');
  });

  it('password change invalidates existing sessions', async () => {
    await createAdmin('ADMIN', 'a@sumt.test');
    const t = await adminLogin(app, 'a@sumt.test');
    const res = await app.inject({ method: 'POST', url: '/api/v1/admin/me/password', headers: bearer(t.accessToken), payload: { currentPassword: TEST_PASSWORD, newPassword: 'N3w!Password-123' } });
    expect(res.statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/api/v1/admin/me', headers: bearer(t.accessToken) })).statusCode).toBe(401);
    await adminLogin(app, 'a@sumt.test', 'N3w!Password-123');
  });

  it('validates input', async () => {
    await createAdmin('ADMIN', 'a@sumt.test');
    const { accessToken } = await adminLogin(app, 'a@sumt.test');
    const res = await app.inject({ method: 'POST', url: '/api/v1/admin/activations/generate', headers: bearer(accessToken), payload: { installationId: 'SUMT-1', licenseDays: -4 } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('VALIDATION_ERROR');
    const nf = await app.inject({ method: 'POST', url: '/api/v1/admin/activations/generate', headers: bearer(accessToken), payload: { installationId: 'SUMT-99999' } });
    expect(nf.statusCode).toBe(404);
  });
});

describe('bootstrap admin', () => {
  it('creates the first SUPERADMIN only when none exists', async () => {
    const { bootstrapAdmin } = await import('../src/services/admin-auth.service.js');
    const log = { info: () => {}, warn: () => {} };
    const ctx = { ...app.ctx, env: { ...app.ctx.env, BOOTSTRAP_ADMIN_EMAIL: 'boss@sumt.test', BOOTSTRAP_ADMIN_PASSWORD: TEST_PASSWORD } };
    await bootstrapAdmin(ctx, log);
    await bootstrapAdmin(ctx, log);
    expect(await prisma.admin.count()).toBe(1);
    expect((await prisma.admin.findFirstOrThrow()).role).toBe('SUPERADMIN');
  });
});
