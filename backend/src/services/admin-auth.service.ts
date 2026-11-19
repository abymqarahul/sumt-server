import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import type { Admin, AdminRole, PrismaClient } from '@prisma/client';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AppContext } from '../context.js';
import { randomToken, sha256Hex } from '../security/crypto.js';
import { forbidden, locked, unauthorized } from '../utils/errors.js';
import { audit } from './audit.service.js';

const ARGON_OPTS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

let dummyHash: string | null = null;

export async function hashPassword(pw: string): Promise<string> {
  return argon2.hash(pw, ARGON_OPTS);
}

export function validatePasswordStrength(pw: string): string | null {
  if (pw.length < 12) return 'Password must be at least 12 characters';
  if (pw.length > 256) return 'Password is too long';
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (classes < 3) return 'Use at least three of: lowercase, uppercase, digits, symbols';
  return null;
}

interface AccessClaims {
  sub: string;
  role: AdminRole;
  tv: number;
  typ: 'access';
}

export function issueAccessToken(ctx: AppContext, admin: Admin): string {
  const claims: AccessClaims = { sub: admin.id, role: admin.role, tv: admin.tokenVersion, typ: 'access' };
  return jwt.sign(claims, ctx.env.JWT_ACCESS_SECRET, {
    algorithm: 'HS256',
    expiresIn: ctx.env.ACCESS_TOKEN_TTL_MIN * 60,
    issuer: 'sumt-backend',
    audience: 'sumt-admin',
  });
}

async function createSession(ctx: AppContext, admin: Admin, req: FastifyRequest) {
  const refreshToken = randomToken(48);
  const session = await ctx.prisma.adminSession.create({
    data: {
      adminId: admin.id,
      refreshTokenHash: sha256Hex(refreshToken),
      userAgent: req.headers['user-agent']?.slice(0, 300) ?? null,
      ip: req.ip,
      expiresAt: new Date(Date.now() + ctx.env.REFRESH_TOKEN_TTL_DAYS * 86400_000),
    },
  });
  return { refreshToken, session };
}

function tokenResponse(ctx: AppContext, admin: Admin, refreshToken: string) {
  return {
    accessToken: issueAccessToken(ctx, admin),
    accessTokenExpiresIn: ctx.env.ACCESS_TOKEN_TTL_MIN * 60,
    refreshToken,
    admin: publicAdmin(admin),
  };
}

export function publicAdmin(a: Admin) {
  return { id: a.id, email: a.email, name: a.name, role: a.role, disabled: a.disabled, lastLoginAt: a.lastLoginAt, createdAt: a.createdAt };
}

export async function login(ctx: AppContext, email: string, password: string, req: FastifyRequest) {
  const { prisma, env } = ctx;
  const admin = await prisma.admin.findUnique({ where: { email: email.toLowerCase().trim() } });
  if (!admin) {
    dummyHash ??= await hashPassword('dummy-password-for-timing-equalisation');
    await argon2.verify(dummyHash, password).catch(() => false);
    throw unauthorized('INVALID_CREDENTIALS', 'Invalid email or password');
  }
  if (admin.lockedUntil && admin.lockedUntil > new Date()) {
    throw locked('ACCOUNT_LOCKED', 'Too many failed logins. Try again later.', { retryAfter: admin.lockedUntil.toISOString() });
  }
  const ok = await argon2.verify(admin.passwordHash, password).catch(() => false);
  if (!ok || admin.disabled) {
    const fails = admin.failedLogins + 1;
    const lock = fails >= env.ADMIN_MAX_FAILED_LOGINS;
    await prisma.admin.update({
      where: { id: admin.id },
      data: lock
        ? { failedLogins: 0, lockedUntil: new Date(Date.now() + env.ADMIN_LOCK_MINUTES * 60_000) }
        : { failedLogins: fails },
    });
    await audit(prisma, { actorType: 'ADMIN', actorId: admin.id, action: 'admin.login_failed', ip: req.ip, meta: { locked: lock, disabled: admin.disabled } });
    throw unauthorized('INVALID_CREDENTIALS', 'Invalid email or password');
  }
  const updated = await prisma.admin.update({
    where: { id: admin.id },
    data: { failedLogins: 0, lockedUntil: null, lastLoginAt: new Date() },
  });
  const { refreshToken } = await createSession(ctx, updated, req);
  await audit(prisma, { actorType: 'ADMIN', actorId: admin.id, action: 'admin.login', ip: req.ip });
  return tokenResponse(ctx, updated, refreshToken);
}

/** Rotating refresh tokens with reuse detection. */
export async function refresh(ctx: AppContext, refreshToken: string, req: FastifyRequest) {
  const { prisma } = ctx;
  const session = await prisma.adminSession.findUnique({
    where: { refreshTokenHash: sha256Hex(refreshToken) },
    include: { admin: true },
  });
  if (!session) throw unauthorized('INVALID_REFRESH_TOKEN', 'Session not found');
  if (session.revokedAt) {
    // A rotated token was presented again → likely stolen. Kill every session for this admin.
    await revokeAllSessions(prisma, session.adminId);
    await audit(prisma, { actorType: 'SYSTEM', action: 'admin.refresh_reuse_detected', targetType: 'admin', targetId: session.adminId, ip: req.ip });
    throw unauthorized('REFRESH_TOKEN_REUSED', 'Session invalidated. Please log in again.');
  }
  if (session.expiresAt < new Date() || session.admin.disabled) {
    throw unauthorized('SESSION_EXPIRED', 'Session expired. Please log in again.');
  }
  const { refreshToken: next, session: newSession } = await createSession(ctx, session.admin, req);
  await prisma.adminSession.update({ where: { id: session.id }, data: { revokedAt: new Date(), replacedById: newSession.id } });
  return tokenResponse(ctx, session.admin, next);
}

export async function logout(ctx: AppContext, refreshToken: string) {
  await ctx.prisma.adminSession.updateMany({
    where: { refreshTokenHash: sha256Hex(refreshToken), revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

export async function revokeAllSessions(prisma: PrismaClient, adminId: string) {
  await prisma.$transaction([
    prisma.adminSession.updateMany({ where: { adminId, revokedAt: null }, data: { revokedAt: new Date() } }),
    prisma.admin.update({ where: { id: adminId }, data: { tokenVersion: { increment: 1 } } }),
  ]);
}

const ROLE_RANK: Record<AdminRole, number> = { VIEWER: 1, ADMIN: 2, SUPERADMIN: 3 };

/** Fastify preHandler factory — authorisation is enforced here, server-side. */
export function requireAdmin(minRole: AdminRole) {
  return async (req: FastifyRequest, _reply: FastifyReply) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) throw unauthorized('AUTH_REQUIRED', 'Admin authentication required');
    let claims: AccessClaims;
    try {
      claims = jwt.verify(auth.slice(7), req.server.ctx.env.JWT_ACCESS_SECRET, {
        algorithms: ['HS256'],
        issuer: 'sumt-backend',
        audience: 'sumt-admin',
      }) as AccessClaims;
    } catch {
      throw unauthorized('INVALID_TOKEN', 'Access token is invalid or expired');
    }
    if (claims.typ !== 'access') throw unauthorized('INVALID_TOKEN', 'Wrong token type');
    const admin = await req.server.ctx.prisma.admin.findUnique({ where: { id: claims.sub } });
    if (!admin || admin.disabled || admin.tokenVersion !== claims.tv) {
      throw unauthorized('INVALID_TOKEN', 'Session is no longer valid');
    }
    if (ROLE_RANK[admin.role] < ROLE_RANK[minRole]) {
      throw forbidden('INSUFFICIENT_ROLE', `This action requires ${minRole} role`);
    }
    req.admin = admin;
  };
}

/** Creates the first SUPERADMIN from env vars if no admin exists yet. */
export async function bootstrapAdmin(ctx: AppContext, log: { info: (m: string) => void; warn: (m: string) => void }) {
  const { BOOTSTRAP_ADMIN_EMAIL: email, BOOTSTRAP_ADMIN_PASSWORD: password } = ctx.env;
  if (!email || !password) return;
  const count = await ctx.prisma.admin.count();
  if (count > 0) {
    log.warn('BOOTSTRAP_ADMIN_* is set but admins already exist; remove these variables from Railway.');
    return;
  }
  const weak = validatePasswordStrength(password);
  if (weak) {
    log.warn(`Bootstrap admin not created: ${weak}`);
    return;
  }
  const admin = await ctx.prisma.admin.create({
    data: { email: email.toLowerCase(), passwordHash: await hashPassword(password), role: 'SUPERADMIN', name: 'Owner' },
  });
  await audit(ctx.prisma, { actorType: 'SYSTEM', action: 'admin.bootstrap', targetType: 'admin', targetId: admin.id });
  log.info(`Bootstrap SUPERADMIN created: ${admin.email}. Now remove BOOTSTRAP_ADMIN_PASSWORD from the environment.`);
}
