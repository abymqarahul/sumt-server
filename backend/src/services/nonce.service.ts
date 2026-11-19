import type { PrismaClient } from '@prisma/client';
import { isUniqueViolation } from '../database/prisma.js';
import { unauthorized } from '../utils/errors.js';

/** Records a nonce; a second use within its lifetime is rejected as a replay. */
export async function consumeNonce(prisma: PrismaClient, nonce: string, installationId: string, ttlSec: number) {
  try {
    await prisma.usedNonce.create({
      data: { nonce, installationId, expiresAt: new Date(Date.now() + ttlSec * 1000) },
    });
  } catch (err) {
    if (isUniqueViolation(err)) throw unauthorized('REPLAY_DETECTED', 'This request was already used');
    throw err;
  }
}

export async function purgeExpiredNonces(prisma: PrismaClient): Promise<number> {
  const res = await prisma.usedNonce.deleteMany({ where: { expiresAt: { lt: new Date() } } });
  return res.count;
}
