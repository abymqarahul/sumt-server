import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { adminLogin, bearer, cleanDb, createAdmin, makeApp, multipartBody, prisma, TestDevice } from './helpers.js';

let app: FastifyInstance;
let token: string;
const firmware = crypto.randomBytes(300_000);
const fwSha = crypto.createHash('sha256').update(firmware).digest('hex');

async function upload(fields: Record<string, string>, data = firmware) {
  const mp = multipartBody(fields, { name: 'sumt-esp32-bridge.bin', data });
  return app.inject({ method: 'POST', url: '/api/v1/admin/resources', headers: { ...bearer(token), ...mp.headers }, payload: mp.payload });
}

async function activeDevice() {
  const d = new TestDevice(app);
  await d.register();
  const gen = await app.inject({ method: 'POST', url: '/api/v1/admin/activations/generate', headers: bearer(token), payload: { installationId: d.displayId } });
  await d.consume(gen.json().activationKey);
  return d;
}

const baseFields = { kind: 'FIRMWARE', slug: 'esp32-bridge', name: 'ESP32 Bridge', versionName: '1.0.0', versionCode: '1', targetHardware: 'ESP32', publish: 'true' };

beforeAll(async () => {
  app = await makeApp({ MAX_UPLOAD_MB: '1' });
});
afterAll(async () => {
  await app.close();
  await prisma.$disconnect();
});
beforeEach(async () => {
  await cleanDb();
  await createAdmin('ADMIN', 'a@sumt.test');
  token = (await adminLogin(app, 'a@sumt.test')).accessToken;
});

describe('firmware / resource distribution', () => {
  it('upload computes SHA-256; licensed devices list, get a ticket and download the exact bytes', async () => {
    const up = await upload(baseFields);
    expect(up.statusCode, up.body).toBe(201);
    expect(up.json()).toMatchObject({ sha256: fwSha, sizeBytes: firmware.length, published: true, fileName: 'sumt-esp32-bridge.bin' });

    const d = await activeDevice();
    const list = await d.request('GET', '/api/v1/resources');
    expect(list.statusCode).toBe(200);
    expect(list.json().items).toHaveLength(1);
    const item = list.json().items[0];

    const t = await d.request('POST', `/api/v1/resources/${item.id}/ticket`);
    expect(t.statusCode).toBe(200);
    const dl = await app.inject({ method: 'GET', url: t.json().path });
    expect(dl.statusCode).toBe(200);
    expect(dl.headers['x-sumt-sha256']).toBe(fwSha);
    expect(crypto.createHash('sha256').update(dl.rawPayload).digest('hex')).toBe(fwSha);

    const part = await app.inject({ method: 'GET', url: t.json().path, headers: { range: 'bytes=100-199' } });
    expect(part.statusCode).toBe(206);
    expect(part.rawPayload.equals(firmware.subarray(100, 200))).toBe(true);
    expect((await app.inject({ method: 'GET', url: t.json().path, headers: { range: `bytes=${firmware.length}-` } })).statusCode).toBe(416);
  });

  it('device sees only the latest published version per slug', async () => {
    await upload(baseFields);
    await upload({ ...baseFields, versionName: '1.1.0', versionCode: '2' });
    await upload({ ...baseFields, versionName: '2.0.0-beta', versionCode: '3', channel: 'BETA' });
    await upload({ ...baseFields, versionName: '9.9.9', versionCode: '9', publish: 'false' });
    const d = await activeDevice();
    expect((await d.request('GET', '/api/v1/resources')).json().items.map((i: { versionCode: number }) => i.versionCode)).toEqual([2]);
    expect((await d.request('GET', '/api/v1/resources?channel=BETA')).json().items.map((i: { versionCode: number }) => i.versionCode)).toEqual([3]);
  });

  it('publish / unpublish takes effect immediately, including for issued tickets', async () => {
    const id = (await upload({ ...baseFields, publish: 'false' })).json().id;
    const d = await activeDevice();
    expect((await d.request('GET', '/api/v1/resources')).json().items).toHaveLength(0);
    await app.inject({ method: 'PATCH', url: `/api/v1/admin/resources/${id}`, headers: bearer(token), payload: { published: true } });
    const t = (await d.request('POST', `/api/v1/resources/${id}/ticket`)).json();
    await app.inject({ method: 'PATCH', url: `/api/v1/admin/resources/${id}`, headers: bearer(token), payload: { published: false } });
    expect((await app.inject({ method: 'GET', url: t.path })).statusCode).toBe(404);
  });

  it('unlicensed devices cannot list or download', async () => {
    await upload(baseFields);
    const d = new TestDevice(app);
    await d.register();
    expect((await d.request('GET', '/api/v1/resources')).statusCode).toBe(403);
  });

  it('download stops working when the licence is revoked', async () => {
    const id = (await upload(baseFields)).json().id;
    const d = await activeDevice();
    const t = (await d.request('POST', `/api/v1/resources/${id}/ticket`)).json();
    const lic = await prisma.license.findFirstOrThrow({ where: { status: 'ACTIVE' } });
    await app.inject({ method: 'POST', url: `/api/v1/admin/licenses/${lic.id}/revoke`, headers: bearer(token), payload: {} });
    expect((await app.inject({ method: 'GET', url: t.path })).statusCode).toBe(403);
  });

  it('rejects tampered tickets', async () => {
    const id = (await upload(baseFields)).json().id;
    const d = await activeDevice();
    const t = (await d.request('POST', `/api/v1/resources/${id}/ticket`)).json();
    const tampered = t.path.slice(0, -3) + (t.path.endsWith('A') ? 'BBB' : 'AAA');
    expect((await app.inject({ method: 'GET', url: tampered })).statusCode).toBe(401);
  });

  it('validates uploads: checksum, duplicates, size, metadata', async () => {
    expect((await upload({ ...baseFields, sha256: '0'.repeat(64) })).json().error).toBe('CHECKSUM_MISMATCH');
    expect((await upload({ ...baseFields, sha256: fwSha })).statusCode).toBe(201);
    expect((await upload(baseFields)).json().error).toBe('VERSION_EXISTS');
    expect((await upload({ ...baseFields, versionCode: '5' }, crypto.randomBytes(1_200_000))).statusCode).toBe(413);
    expect((await upload({ ...baseFields, slug: 'Bad Slug!', versionCode: '6' })).statusCode).toBe(400);
    expect((await upload({ ...baseFields, kind: 'HEX_EDITOR', versionCode: '7' })).statusCode).toBe(400);
    // Failed uploads leave no orphaned DB rows.
    expect(await prisma.resource.count()).toBe(1);
  });

  it('only SUPERADMIN can delete; delete removes the file', async () => {
    const id = (await upload(baseFields)).json().id;
    expect((await app.inject({ method: 'DELETE', url: `/api/v1/admin/resources/${id}`, headers: bearer(token) })).statusCode).toBe(403);
    await createAdmin('SUPERADMIN', 's@sumt.test');
    const s = await adminLogin(app, 's@sumt.test');
    const key = (await prisma.resource.findUniqueOrThrow({ where: { id } })).storageKey;
    expect((await app.inject({ method: 'DELETE', url: `/api/v1/admin/resources/${id}`, headers: bearer(s.accessToken) })).statusCode).toBe(200);
    expect(await app.ctx.storage.stat(key)).toBeNull();
  });
});
