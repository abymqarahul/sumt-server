import Fastify, { type FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import multipart from '@fastify/multipart';
import cors from '@fastify/cors';
import { ZodError } from 'zod';
import { Prisma } from '@prisma/client';
import type { Env } from './config/env.js';
import type { AppContext } from './context.js';
import { createPrisma } from './database/prisma.js';
import { LicenseSigner } from './security/crypto.js';
import { LocalStorage } from './storage/local.js';
import { IntegrityVerifier } from './services/integrity.service.js';
import { AppError } from './utils/errors.js';
import { publicRoutes } from './routes/public.routes.js';
import { deviceRoutes } from './routes/device.routes.js';
import { adminRoutes } from './routes/admin.routes.js';
import { purgeExpiredNonces } from './services/nonce.service.js';
import './context.js';

export async function buildApp(env: Env, overrides: Partial<AppContext> = {}): Promise<FastifyInstance> {
  const app = Fastify({
    trustProxy: true,
    maxParamLength: 512,
    bodyLimit: 256 * 1024,
    logger:
      env.LOG_LEVEL === 'silent'
        ? false
        : {
            level: env.LOG_LEVEL,
            redact: ['req.headers.authorization', 'req.headers["x-sumt-signature"]', 'req.body.password', 'req.body.activationKey', 'req.body.refreshToken'],
          },
    genReqId: () => crypto.randomUUID(),
  });

  const storage = overrides.storage ?? new LocalStorage(env.STORAGE_DIR);
  await storage.init();
  const ctx: AppContext = {
    env,
    prisma: overrides.prisma ?? createPrisma(env.DATABASE_URL),
    signer: overrides.signer ?? new LicenseSigner(env.LICENSE_SIGNING_PRIVATE_KEY),
    storage,
    integrity: overrides.integrity ?? new IntegrityVerifier(env),
  };
  app.decorate('ctx', ctx);

  // Keep the exact request body so device signatures can be verified over it.
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, done) => {
    const raw = body as string;
    req.rawBody = raw;
    if (raw.length === 0) return done(null, {});
    try {
      done(null, JSON.parse(raw));
    } catch {
      done(new AppError(400, 'INVALID_JSON', 'Request body is not valid JSON'), undefined);
    }
  });

  await app.register(helmet, { contentSecurityPolicy: false });
  if (env.CORS_ORIGINS) {
    await app.register(cors, { origin: env.CORS_ORIGINS.split(',').map((s) => s.trim()), credentials: false });
  }
  await app.register(rateLimit, {
    global: true,
    max: env.RATE_LIMIT_GLOBAL_PER_MIN,
    timeWindow: '1 minute',
    errorResponseBuilder: (_req, c) => ({ statusCode: 429, error: 'RATE_LIMITED', message: `Too many requests. Retry in ${Math.ceil(c.ttl / 1000)} s.` }),
  });
  await app.register(multipart, { limits: { fileSize: env.MAX_UPLOAD_MB * 1024 * 1024, files: 1, fields: 20, fieldSize: 10_000 } });

  // HTTPS only in production (Railway terminates TLS and sets X-Forwarded-Proto).
  if (env.NODE_ENV === 'production' && env.ENFORCE_HTTPS) {
    app.addHook('onRequest', async (req, reply) => {
      if (req.headers['x-forwarded-proto'] === 'http') {
        return reply.code(400).send({ statusCode: 400, error: 'HTTPS_REQUIRED', message: 'Use HTTPS' });
      }
    });
    app.addHook('onSend', async (_req, reply) => {
      reply.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    });
  }

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({
        statusCode: 400,
        error: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      });
    }
    if (err instanceof AppError) {
      if (err.statusCode >= 500) req.log.error(err);
      return reply.code(err.statusCode).send({ statusCode: err.statusCode, error: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) });
    }
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2025') {
      return reply.code(404).send({ statusCode: 404, error: 'NOT_FOUND', message: 'Record not found' });
    }
    const status = (err as { statusCode?: number }).statusCode;
    if (status && status >= 400 && status < 500) {
      return reply.code(status).send({ statusCode: status, error: (err as { code?: string }).code ?? 'BAD_REQUEST', message: (err as Error).message });
    }
    req.log.error({ err }, 'Unhandled error');
    return reply.code(500).send({ statusCode: 500, error: 'INTERNAL_ERROR', message: 'Internal server error', requestId: req.id });
  });

  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ statusCode: 404, error: 'NOT_FOUND', message: 'Route not found' }));

  await app.register(
    async (v1) => {
      await v1.register(publicRoutes);
      await v1.register(deviceRoutes);
      await v1.register(adminRoutes, { prefix: '/admin' });
    },
    { prefix: '/api/v1' },
  );

  const timer = setInterval(() => {
    purgeExpiredNonces(ctx.prisma).catch((e) => app.log.warn({ err: e }, 'nonce purge failed'));
  }, 10 * 60_000);
  timer.unref();
  app.addHook('onClose', async () => {
    clearInterval(timer);
    if (!overrides.prisma) await ctx.prisma.$disconnect();
  });

  return app;
}
