import type { Installation, License, PrismaClient, Prisma } from '@prisma/client';
import type { AppContext } from '../context.js';

type Db = PrismaClient | Prisma.TransactionClient;

export type EffectiveStatus = 'PENDING' | 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'BLOCKED';

export async function getActiveLicense(db: Db, installationId: string): Promise<License | null> {
  return db.license.findFirst({
    where: { installationId, status: 'ACTIVE' },
    orderBy: { issuedAt: 'desc' },
  });
}

export function effectiveStatus(inst: Installation, license: License | null, now = new Date()): EffectiveStatus {
  if (inst.status === 'BLOCKED') return 'BLOCKED';
  if (license) {
    if (license.expiresAt && license.expiresAt.getTime() <= now.getTime()) return 'EXPIRED';
    return 'ACTIVE';
  }
  if (inst.status === 'REVOKED') return 'REVOKED';
  return 'PENDING';
}

export interface LicenseView {
  installationId: string;
  displayId: string;
  status: EffectiveStatus;
  plan: string | null;
  expiresAt: string | null;
  licenseToken: string | null;
  offlineGraceUntil: string | null;
  serverTime: string;
  message: string;
}

const MESSAGES: Record<EffectiveStatus, string> = {
  PENDING: 'Activation required. Share your installation ID with your SUMT provider.',
  ACTIVE: 'Licence active.',
  EXPIRED: 'Your licence has expired. Contact your SUMT provider to renew.',
  REVOKED: 'This licence was revoked. Contact your SUMT provider.',
  BLOCKED: 'This installation has been blocked. Contact your SUMT provider.',
};

export function buildLicenseView(ctx: AppContext, inst: Installation, license: License | null, now = new Date()): LicenseView {
  const status = effectiveStatus(inst, license, now);
  let token: string | null = null;
  let grace: Date | null = null;
  if (status === 'ACTIVE' && license) {
    grace = new Date(now.getTime() + ctx.env.OFFLINE_GRACE_HOURS * 3600_000);
    if (license.expiresAt && license.expiresAt < grace) grace = license.expiresAt;
    token = ctx.signer.sign({
      v: 1,
      iid: inst.id,
      did: inst.displayId,
      kfp: inst.keyFingerprint,
      st: 'ACTIVE',
      lid: license.id,
      plan: license.plan,
      iat: Math.floor(now.getTime() / 1000),
      exp: license.expiresAt ? Math.floor(license.expiresAt.getTime() / 1000) : null,
      gu: Math.floor(grace.getTime() / 1000),
    });
  }
  return {
    installationId: inst.id,
    displayId: inst.displayId,
    status,
    plan: license?.plan ?? null,
    expiresAt: license?.expiresAt?.toISOString() ?? null,
    licenseToken: token,
    offlineGraceUntil: grace?.toISOString() ?? null,
    serverTime: now.toISOString(),
    message: MESSAGES[status],
  };
}
