import type { PrismaClient, Installation, Admin } from '@prisma/client';
import type { Env } from './config/env.js';
import type { LicenseSigner } from './security/crypto.js';
import type { LocalStorage } from './storage/local.js';
import type { IntegrityVerifier } from './services/integrity.service.js';

export interface AppContext {
  env: Env;
  prisma: PrismaClient;
  signer: LicenseSigner;
  storage: LocalStorage;
  integrity: IntegrityVerifier;
}

declare module 'fastify' {
  interface FastifyInstance {
    ctx: AppContext;
  }
  interface FastifyRequest {
    rawBody?: string;
    installation?: Installation;
    admin?: Admin;
  }
}
