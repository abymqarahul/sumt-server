import type { Installation, PrismaClient } from '@prisma/client';
import { isUniqueViolation } from '../database/prisma.js';
import type { ParsedPublicKey } from '../security/crypto.js';
import { audit } from './audit.service.js';
import { notFound } from '../utils/errors.js';

export interface DeviceInfo {
  manufacturer?: string;
  model?: string;
  sdkInt?: number;
  appVersionName?: string;
  appVersionCode?: number;
}

export function formatDisplayId(seq: number | bigint): string {
  return `SUMT-${seq.toString()}`;
}

/**
 * Registers an installation for a Keystore public key. Idempotent: the same key always maps to the
 * same installation (an app restart or a retried request never creates a duplicate).
 */
export async function registerInstallation(
  prisma: PrismaClient,
  key: ParsedPublicKey,
  device: DeviceInfo,
  ip: string,
  integrityVerdict: string | null,
): Promise<{ installation: Installation; created: boolean }> {
  const existing = await prisma.installation.findUnique({ where: { keyFingerprint: key.fingerprint } });
  if (existing) {
    const updated = await prisma.installation.update({
      where: { id: existing.id },
      data: { lastSeenAt: new Date(), lastSeenIp: ip, ...deviceData(device), ...(integrityVerdict ? { integrityVerdict } : {}) },
    });
    return { installation: updated, created: false };
  }

  try {
    const installation = await prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<{ seq: bigint }[]>`SELECT nextval('"installations_seq_seq"') AS seq`;
      const seq = Number(rows[0]!.seq);
      const inst = await tx.installation.create({
        data: {
          seq,
          displayId: formatDisplayId(seq),
          publicKey: key.spkiBase64,
          keyFingerprint: key.fingerprint,
          integrityVerdict,
          lastSeenAt: new Date(),
          lastSeenIp: ip,
          ...deviceData(device),
        },
      });
      await audit(tx, {
        actorType: 'DEVICE',
        actorId: inst.id,
        action: 'installation.register',
        targetType: 'installation',
        targetId: inst.id,
        ip,
        meta: { displayId: inst.displayId, model: device.model ?? null, integrity: integrityVerdict },
      });
      return inst;
    });
    return { installation, created: true };
  } catch (err) {
    // Two concurrent first-launch requests with the same key: return the winner.
    if (isUniqueViolation(err)) {
      const inst = await prisma.installation.findUnique({ where: { keyFingerprint: key.fingerprint } });
      if (inst) return { installation: inst, created: false };
    }
    throw err;
  }
}

function deviceData(d: DeviceInfo) {
  return {
    deviceManufacturer: d.manufacturer ?? undefined,
    deviceModel: d.model ?? undefined,
    deviceSdkInt: d.sdkInt ?? undefined,
    appVersionName: d.appVersionName ?? undefined,
    appVersionCode: d.appVersionCode ?? undefined,
  };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Accepts the internal UUID or the display ID (SUMT-10001, case-insensitive, also bare "10001"). */
export async function resolveInstallation(prisma: PrismaClient, ref: string): Promise<Installation> {
  const r = ref.trim();
  let inst: Installation | null = null;
  if (UUID_RE.test(r)) {
    inst = await prisma.installation.findUnique({ where: { id: r } });
  } else {
    const m = /^(?:SUMT-?)?(\d{1,10})$/i.exec(r);
    if (m) inst = await prisma.installation.findUnique({ where: { seq: Number(m[1]) } });
  }
  if (!inst) throw notFound('INSTALLATION_NOT_FOUND', `Installation ${r} not found`);
  return inst;
}
