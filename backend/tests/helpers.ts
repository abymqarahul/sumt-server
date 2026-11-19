import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { PrismaClient } from '@prisma/client';
import { loadEnv, type Env } from '../src/config/env.js';
import { buildApp } from '../src/app.js';
import { canonicalRequest, registrationMessage, sha256Hex } from '../src/security/crypto.js';
import { hashPassword } from '../src/services/admin-auth.service.js';

process.env.TEST_DATABASE_URL ??= 'postgresql://sumt:sumt@localhost:5432/sumt_test';

export const TEST_PASSWORD = 'Str0ng!Passw0rd';

export function testEnv(overrides: Record<string, string> = {}): Env {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return loadEnv({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    DATABASE_URL: process.env.TEST_DATABASE_URL!,
    LICENSE_SIGNING_PRIVATE_KEY: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    ACTIVATION_KEY_PEPPER: crypto.randomBytes(32).toString('hex'),
    JWT_ACCESS_SECRET: crypto.randomBytes(32).toString('hex'),
    DOWNLOAD_TICKET_SECRET: crypto.randomBytes(32).toString('hex'),
    STORAGE_DIR: path.join(os.tmpdir(), `sumt-test-${crypto.randomUUID()}`),
    RATE_LIMIT_GLOBAL_PER_MIN: '100000',
    RATE_LIMIT_AUTH_PER_MIN: '100000',
    RATE_LIMIT_REGISTER_PER_MIN: '100000',
    ...overrides,
  });
}

export const prisma = new PrismaClient({ datasources: { db: { url: process.env.TEST_DATABASE_URL } } });

export async function cleanDb() {
  await prisma.$executeRawUnsafe(
    'TRUNCATE audit_logs, used_nonces, licenses, activation_keys, admin_sessions, resources, installations, admins RESTART IDENTITY CASCADE',
  );
  await prisma.$executeRawUnsafe('ALTER SEQUENCE "installations_seq_seq" RESTART WITH 10001');
}

export async function makeApp(overrides: Record<string, string> = {}) {
  const env = testEnv(overrides);
  const app = await buildApp(env, { prisma });
  await app.ready();
  return app;
}

/** Simulates the Android app: a Keystore-like EC P-256 key that signs every request. */
export class TestDevice {
  readonly keys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  readonly spki = this.keys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  installationId = '';
  displayId = '';
  clockOffsetMs = 0;

  constructor(private readonly app: FastifyInstance, public model = 'Pixel Test') {}

  sign(message: string) {
    return crypto.sign('sha256', Buffer.from(message), { key: this.keys.privateKey, dsaEncoding: 'der' }).toString('base64');
  }

  async register(extra: Record<string, unknown> = {}) {
    const timestamp = String(Date.now() + this.clockOffsetMs);
    const nonce = crypto.randomBytes(16).toString('base64url');
    const res = await this.app.inject({
      method: 'POST',
      url: '/api/v1/installations/register',
      payload: {
        publicKey: this.spki,
        timestamp,
        nonce,
        signature: this.sign(registrationMessage(this.spki, timestamp, nonce)),
        device: { manufacturer: 'Google', model: this.model, sdkInt: 34, appVersionName: '1.0.0', appVersionCode: 1 },
        ...extra,
      },
    });
    if (res.statusCode < 300) {
      const b = res.json();
      this.installationId = b.installationId;
      this.displayId = b.displayId;
    }
    return res;
  }

  signedHeaders(method: string, url: string, body = '', opts: { nonce?: string; timestamp?: string } = {}) {
    const timestamp = opts.timestamp ?? String(Date.now() + this.clockOffsetMs);
    const nonce = opts.nonce ?? crypto.randomBytes(16).toString('base64url');
    return {
      'x-sumt-installation': this.installationId,
      'x-sumt-timestamp': timestamp,
      'x-sumt-nonce': nonce,
      'x-sumt-signature': this.sign(canonicalRequest(method, url, timestamp, nonce, sha256Hex(body))),
    };
  }

  async request(method: 'GET' | 'POST', url: string, payload?: object) {
    const body = payload ? JSON.stringify(payload) : '';
    return this.app.inject({
      method,
      url,
      headers: { ...this.signedHeaders(method, url, body), ...(payload ? { 'content-type': 'application/json' } : {}) },
      payload: body || undefined,
    });
  }

  consume(activationKey: string) {
    return this.request('POST', '/api/v1/activations/consume', { activationKey });
  }

  verify() {
    return this.request('GET', '/api/v1/licenses/verify');
  }
}

export async function createAdmin(role: 'SUPERADMIN' | 'ADMIN' | 'VIEWER' = 'SUPERADMIN', email = `${role.toLowerCase()}@sumt.test`) {
  return prisma.admin.create({ data: { email, role, passwordHash: await hashPassword(TEST_PASSWORD) } });
}

export async function adminLogin(app: FastifyInstance, email: string, password = TEST_PASSWORD) {
  const res = await app.inject({ method: 'POST', url: '/api/v1/admin/login', payload: { email, password } });
  if (res.statusCode !== 200) throw new Error(`login failed: ${res.statusCode} ${res.body}`);
  return res.json() as { accessToken: string; refreshToken: string };
}

export function bearer(token: string) {
  return { authorization: `Bearer ${token}` };
}

export function multipartBody(fields: Record<string, string>, file: { name: string; data: Buffer; type?: string }) {
  const boundary = `----sumt${crypto.randomBytes(8).toString('hex')}`;
  const chunks: Buffer[] = [];
  for (const [k, v] of Object.entries(fields)) {
    chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`));
  }
  chunks.push(
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${file.name}"\r\nContent-Type: ${file.type ?? 'application/octet-stream'}\r\n\r\n`,
    ),
  );
  chunks.push(file.data, Buffer.from(`\r\n--${boundary}--\r\n`));
  return { payload: Buffer.concat(chunks), headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
}
