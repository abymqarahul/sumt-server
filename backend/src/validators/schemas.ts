import { z } from 'zod';

const trimmed = (max: number) => z.string().trim().max(max);

export const registerSchema = z.object({
  publicKey: z.string().min(60).max(400),
  timestamp: z.string().regex(/^\d{10,16}$/),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/),
  signature: z.string().min(8).max(200),
  integrityToken: z.string().max(10000).optional(),
  device: z
    .object({
      manufacturer: trimmed(80).optional(),
      model: trimmed(80).optional(),
      sdkInt: z.number().int().min(1).max(100).optional(),
      appVersionName: trimmed(40).optional(),
      appVersionCode: z.number().int().min(0).max(2_100_000_000).optional(),
    })
    .default({}),
});

export const consumeSchema = z.object({
  activationKey: z.string().min(16).max(40),
});

export const loginSchema = z.object({
  email: z.string().email().max(200),
  password: z.string().min(1).max(256),
});

export const refreshSchema = z.object({ refreshToken: z.string().min(20).max(200) });

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(256),
  newPassword: z.string().min(12).max(256),
});

export const listInstallationsSchema = z.object({
  status: z.enum(['PENDING', 'ACTIVE', 'BLOCKED', 'REVOKED', 'EXPIRED']).optional(),
  q: trimmed(100).optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(25),
  sort: z.enum(['createdAt', 'lastSeenAt', 'seq']).default('createdAt'),
  order: z.enum(['asc', 'desc']).default('desc'),
});

export const updateInstallationSchema = z.object({
  customerName: trimmed(120).nullable().optional(),
  customerPhone: trimmed(40).nullable().optional(),
  notes: trimmed(2000).nullable().optional(),
});

export const generateKeySchema = z.object({
  installationId: z.string().trim().min(1).max(64),
  /** null or omitted = lifetime licence */
  licenseDays: z.number().int().min(1).max(3650).nullable().optional(),
  keyValidHours: z.number().int().min(1).max(720).optional(),
  plan: trimmed(40).regex(/^[A-Z0-9_]+$/).optional(),
});

export const reasonSchema = z.object({ reason: trimmed(500).optional() });

export const updateLicenseSchema = z.object({
  /** ISO date-time; null = lifetime */
  expiresAt: z.string().datetime({ offset: true }).nullable(),
});

export const transferSchema = z.object({ toInstallationId: z.string().trim().min(1).max(64), reason: trimmed(500).optional() });

export const createAdminSchema = z.object({
  email: z.string().email().max(200),
  name: trimmed(100).optional(),
  password: z.string().min(12).max(256),
  role: z.enum(['SUPERADMIN', 'ADMIN', 'VIEWER']).default('ADMIN'),
});

export const updateAdminSchema = z.object({
  disabled: z.boolean().optional(),
  role: z.enum(['SUPERADMIN', 'ADMIN', 'VIEWER']).optional(),
  name: trimmed(100).optional(),
});

export const resourceMetaSchema = z.object({
  kind: z.enum(['FIRMWARE', 'REPAIR_DATA', 'WIRING_DIAGRAM', 'KNOWLEDGE_BASE', 'APP_UPDATE']),
  slug: z.string().trim().min(2).max(64).regex(/^[a-z0-9][a-z0-9._-]*$/),
  name: trimmed(120).min(1),
  versionName: trimmed(40).min(1),
  versionCode: z.coerce.number().int().min(1).max(2_100_000_000),
  channel: z.enum(['STABLE', 'BETA']).default('STABLE'),
  targetHardware: trimmed(80).optional(),
  minAppVersionCode: z.coerce.number().int().min(0).optional(),
  releaseNotes: trimmed(5000).optional(),
  publish: z
    .enum(['true', 'false'])
    .optional()
    .transform((v) => v === 'true'),
});

export const updateResourceSchema = z.object({
  published: z.boolean().optional(),
  name: trimmed(120).min(1).optional(),
  releaseNotes: trimmed(5000).nullable().optional(),
  targetHardware: trimmed(80).nullable().optional(),
  minAppVersionCode: z.number().int().min(0).nullable().optional(),
});

export const deviceResourceQuery = z.object({
  kind: z.enum(['FIRMWARE', 'REPAIR_DATA', 'WIRING_DIAGRAM', 'KNOWLEDGE_BASE', 'APP_UPDATE']).optional(),
  channel: z.enum(['STABLE', 'BETA']).default('STABLE'),
});

export const auditQuery = z.object({
  action: trimmed(80).optional(),
  targetId: trimmed(64).optional(),
  actorId: trimmed(64).optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(200).default(50),
});

export const pageQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(50),
});
