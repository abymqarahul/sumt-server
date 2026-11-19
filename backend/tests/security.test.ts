import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { cleanDb, createAdmin, makeApp, prisma, TEST_PASSWORD, TestDevice } from './helpers.js';

beforeEach(async () => {
  await cleanDb();
});
afterAll(async () => {
  await prisma.$disconnect();
});

describe('rate limiting (production-like limits)', () => {
  it('throttles admin login attempts per IP', async () => {
    const app = await makeApp({ RATE_LIMIT_AUTH_PER_MIN: '3' });
    await createAdmin('ADMIN', 'a@sumt.test');
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) {
      codes.push((await app.inject({ method: 'POST', url: '/api/v1/admin/login', payload: { email: 'x@sumt.test', password: 'nope' } })).statusCode);
    }
    expect(codes.slice(0, 3)).toEqual([401, 401, 401]);
    expect(codes[4]).toBe(429);
    await app.close();
  });

  it('throttles activation attempts', async () => {
    const app = await makeApp({ RATE_LIMIT_AUTH_PER_MIN: '2', ACTIVATION_MAX_FAILURES: '50' });
    const d = new TestDevice(app);
    await d.register();
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push((await d.consume('SUMT-0000-0000-0000-0000')).statusCode);
    expect(codes).toContain(429);
    await app.close();
  });
});

describe('transport security', () => {
  it('rejects plain HTTP in production and sets HSTS on HTTPS', async () => {
    const app = await makeApp({ NODE_ENV: 'production' });
    const http = await app.inject({ method: 'GET', url: '/api/v1/health', headers: { 'x-forwarded-proto': 'http' } });
    expect(http.statusCode).toBe(400);
    const https = await app.inject({ method: 'GET', url: '/api/v1/health', headers: { 'x-forwarded-proto': 'https' } });
    expect(https.statusCode).toBe(200);
    expect(https.headers['strict-transport-security']).toContain('max-age');
    await app.close();
  });

  it('never leaks secrets or stack traces in errors', async () => {
    const app = await makeApp();
    const res = await app.inject({ method: 'POST', url: '/api/v1/admin/login', headers: { 'content-type': 'application/json' }, payload: '{bad json' });
    expect(res.statusCode).toBe(400);
    expect(res.body).not.toMatch(/at .*\.ts/);
    const login = await app.inject({ method: 'POST', url: '/api/v1/admin/login', payload: { email: 'a@sumt.test', password: TEST_PASSWORD } });
    expect(login.body).not.toContain('passwordHash');
    await app.close();
  });
});
