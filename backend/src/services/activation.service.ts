import type { Admin, Installation, License, Prisma } from '@prisma/client';
import type { AppContext } from '../context.js';
import { generateActivationKey, hashActivationKey, normalizeActivationKey } from '../security/crypto.js';
import { AppError, badRequest, conflict, locked } from '../utils/errors.js';
import { audit } from './audit.service.js';

export interface GenerateKeyInput {
  installation: Installation;
  admin: Admin;
  licenseDays: number | null;
  keyValidHours: number;
  plan: string;
  ip: string;
}

export async function generateKey(ctx: AppContext, input: GenerateKeyInput) {
  const { installation, admin } = input;
  if (installation.status === 'BLOCKED') {
    throw conflict('INSTALLATION_BLOCKED', 'Unblock this installation before generating a key');
  }
  const plain = generateActivationKey();
  const normalized = normalizeActivationKey(plain)!;
  const keyHash = hashActivationKey(normalized, ctx.env.ACTIVATION_KEY_PEPPER);
  const expiresAt = new Date(Date.now() + input.keyValidHours * 3600_000);

  const key = await ctx.prisma.$transaction(async (tx) => {
    // Only one live key per installation: older unused keys stop working.
    const revoked = await tx.activationKey.updateMany({
      where: { installationId: installation.id, consumedAt: null, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    const k = await tx.activationKey.create({
      data: {
        installationId: installation.id,
        keyHash,
        keyHint: normalized.slice(-4),
        licenseDurationDays: input.licenseDays,
        plan: input.plan,
        createdById: admin.id,
        expiresAt,
      },
    });
    await audit(tx, {
      actorType: 'ADMIN',
      actorId: admin.id,
      action: 'activation_key.generate',
      targetType: 'installation',
      targetId: installation.id,
      ip: input.ip,
      meta: {
        keyId: k.id,
        keyHint: k.keyHint,
        licenseDays: input.licenseDays,
        validHours: input.keyValidHours,
        supersededKeys: revoked.count,
      },
    });
    return k;
  });

  return {
    activationKey: plain,
    keyId: key.id,
    keyHint: key.keyHint,
    expiresAt: key.expiresAt.toISOString(),
    licenseDays: key.licenseDurationDays,
    plan: key.plan,
    installation: { id: installation.id, displayId: installation.displayId },
  };
}

type ConsumeOutcome =
  | { ok: true; license: License; installation: Installation }
  | { ok: false; error: AppError; countFailure: boolean };

/**
 * One-time, device-bound key consumption.
 *  - The key must belong to *this* installation (anti-sharing).
 *  - Consumption is a single conditional UPDATE inside a transaction, with the installation row
 *    locked FOR UPDATE, so two simultaneous requests can never both succeed.
 */
export async function consumeKey(ctx: AppContext, installation: Installation, rawKey: string, ip: string) {
  const { prisma, env } = ctx;
  const now = new Date();

  if (installation.activationLockedUntil && installation.activationLockedUntil > now) {
    throw locked('ACTIVATION_LOCKED', 'Too many failed attempts. Try again later.', {
      retryAfter: installation.activationLockedUntil.toISOString(),
    });
  }

  const normalized = normalizeActivationKey(rawKey);
  if (!normalized) {
    await registerFailure(ctx, installation.id, ip, 'malformed');
    throw badRequest('INVALID_KEY_FORMAT', 'Activation key format is invalid');
  }
  const keyHash = hashActivationKey(normalized, env.ACTIVATION_KEY_PEPPER);

  const outcome: ConsumeOutcome = await prisma.$transaction(
    async (tx): Promise<ConsumeOutcome> => {
      const rows = await tx.$queryRaw<{ status: string; activationLockedUntil: Date | null }[]>`
        SELECT status, "activationLockedUntil" FROM installations WHERE id = ${installation.id}::uuid FOR UPDATE`;
      const row = rows[0];
      if (!row) return { ok: false, error: badRequest('INSTALLATION_NOT_FOUND', 'Installation not found'), countFailure: false };
      if (row.status === 'BLOCKED') {
        return { ok: false, error: new AppError(403, 'INSTALLATION_BLOCKED', 'This installation is blocked'), countFailure: false };
      }

      const updated = await tx.activationKey.updateMany({
        where: { keyHash, installationId: installation.id, consumedAt: null, revokedAt: null, expiresAt: { gt: now } },
        data: { consumedAt: now, consumedIp: ip },
      });

      if (updated.count !== 1) {
        const key = await tx.activationKey.findUnique({ where: { keyHash } });
        // Keys of *other* installations are reported exactly like unknown keys (no oracle).
        if (!key || key.installationId !== installation.id) {
          return { ok: false, error: badRequest('INVALID_KEY', 'Activation key is not valid for this installation'), countFailure: true };
        }
        if (key.consumedAt) return { ok: false, error: conflict('KEY_ALREADY_USED', 'This activation key has already been used'), countFailure: true };
        if (key.revokedAt) return { ok: false, error: badRequest('KEY_REVOKED', 'This activation key was replaced or revoked'), countFailure: true };
        return { ok: false, error: badRequest('KEY_EXPIRED', 'This activation key has expired. Ask for a new key.'), countFailure: true };
      }

      const key = (await tx.activationKey.findUnique({ where: { keyHash } }))!;

      // Renewal: a new key on an already-active installation extends from the current expiry.
      const current = await tx.license.findFirst({ where: { installationId: installation.id, status: 'ACTIVE' }, orderBy: { issuedAt: 'desc' } });
      let base = now;
      if (current?.expiresAt && current.expiresAt > now) base = current.expiresAt;
      const expiresAt = key.licenseDurationDays == null ? null : new Date(base.getTime() + key.licenseDurationDays * 86400_000);

      await tx.license.updateMany({
        where: { installationId: installation.id, status: 'ACTIVE' },
        data: { status: 'REVOKED', revokedAt: now, revokeReason: 'Superseded by new activation' },
      });
      const license = await tx.license.create({
        data: { installationId: installation.id, plan: key.plan, expiresAt, activationKeyId: key.id },
      });
      const inst = await tx.installation.update({
        where: { id: installation.id },
        data: { status: 'ACTIVE', activatedAt: now, failedActivationAttempts: 0, activationLockedUntil: null, lastSeenAt: now, lastSeenIp: ip },
      });
      await audit(tx, {
        actorType: 'DEVICE',
        actorId: installation.id,
        action: 'activation_key.consume',
        targetType: 'installation',
        targetId: installation.id,
        ip,
        meta: { keyId: key.id, licenseId: license.id, expiresAt: expiresAt?.toISOString() ?? null, renewal: Boolean(current) },
      });
      return { ok: true, license, installation: inst };
    },
    { isolationLevel: 'ReadCommitted' as Prisma.TransactionIsolationLevel },
  );

  if (!outcome.ok) {
    if (outcome.countFailure) await registerFailure(ctx, installation.id, ip, outcome.error.code);
    throw outcome.error;
  }
  return outcome;
}

async function registerFailure(ctx: AppContext, installationId: string, ip: string, reason: string) {
  const { prisma, env } = ctx;
  const inst = await prisma.installation.update({
    where: { id: installationId },
    data: { failedActivationAttempts: { increment: 1 } },
  });
  let lockedUntil: Date | null = null;
  if (inst.failedActivationAttempts >= env.ACTIVATION_MAX_FAILURES) {
    lockedUntil = new Date(Date.now() + env.ACTIVATION_LOCK_MINUTES * 60_000);
    await prisma.installation.update({
      where: { id: installationId },
      data: { activationLockedUntil: lockedUntil, failedActivationAttempts: 0 },
    });
  }
  await audit(prisma, {
    actorType: 'DEVICE',
    actorId: installationId,
    action: 'activation_key.failed',
    targetType: 'installation',
    targetId: installationId,
    ip,
    meta: { reason, attempts: inst.failedActivationAttempts, lockedUntil: lockedUntil?.toISOString() ?? null },
  });
}
