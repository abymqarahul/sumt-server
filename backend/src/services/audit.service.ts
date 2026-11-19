import type { ActorType, Prisma, PrismaClient } from '@prisma/client';

type Db = PrismaClient | Prisma.TransactionClient;

export interface AuditEntry {
  actorType: ActorType;
  actorId?: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  ip?: string;
  meta?: Prisma.InputJsonValue;
}

export async function audit(db: Db, e: AuditEntry): Promise<void> {
  await db.auditLog.create({
    data: {
      actorType: e.actorType,
      actorId: e.actorId ?? null,
      action: e.action,
      targetType: e.targetType ?? null,
      targetId: e.targetId ?? null,
      ip: e.ip ?? null,
      meta: e.meta,
    },
  });
}
