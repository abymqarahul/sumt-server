import { z } from 'zod';

const bool = (def: boolean) =>
  z
    .enum(['true', 'false', '1', '0'])
    .optional()
    .transform((v) => (v === undefined ? def : v === 'true' || v === '1'));

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  HOST: z.string().default('0.0.0.0'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  /** base64 of PKCS#8 DER (EC P-256). Generate with `npm run keys:generate`. */
  LICENSE_SIGNING_PRIVATE_KEY: z.string().min(40, 'LICENSE_SIGNING_PRIVATE_KEY is required'),
  /** HMAC pepper for activation key hashes (>= 32 chars). */
  ACTIVATION_KEY_PEPPER: z.string().min(32, 'ACTIVATION_KEY_PEPPER must be at least 32 characters'),
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters'),
  DOWNLOAD_TICKET_SECRET: z.string().min(32, 'DOWNLOAD_TICKET_SECRET must be at least 32 characters'),

  ACCESS_TOKEN_TTL_MIN: z.coerce.number().int().min(1).max(120).default(15),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(30),
  OFFLINE_GRACE_HOURS: z.coerce.number().int().min(0).max(24 * 30).default(72),
  REQUEST_CLOCK_SKEW_SEC: z.coerce.number().int().min(30).max(3600).default(300),
  ACTIVATION_MAX_FAILURES: z.coerce.number().int().min(3).max(100).default(10),
  ACTIVATION_LOCK_MINUTES: z.coerce.number().int().min(1).max(24 * 60).default(30),
  ADMIN_MAX_FAILED_LOGINS: z.coerce.number().int().min(3).max(50).default(5),
  ADMIN_LOCK_MINUTES: z.coerce.number().int().min(1).max(24 * 60).default(15),
  DEFAULT_KEY_VALID_HOURS: z.coerce.number().int().min(1).max(24 * 30).default(72),

  RATE_LIMIT_GLOBAL_PER_MIN: z.coerce.number().int().min(10).default(300),
  RATE_LIMIT_AUTH_PER_MIN: z.coerce.number().int().min(1).default(10),
  RATE_LIMIT_REGISTER_PER_MIN: z.coerce.number().int().min(1).default(20),

  STORAGE_DIR: z.string().default('./data/resources'),
  MAX_UPLOAD_MB: z.coerce.number().int().min(1).max(2048).default(512),
  DOWNLOAD_TICKET_TTL_SEC: z.coerce.number().int().min(30).max(3600).default(600),
  PUBLIC_BASE_URL: z.string().url().optional(),

  ENFORCE_HTTPS: bool(true),
  CORS_ORIGINS: z.string().optional(),

  BOOTSTRAP_ADMIN_EMAIL: z.string().email().optional(),
  BOOTSTRAP_ADMIN_PASSWORD: z.string().min(12).optional(),

  INTEGRITY_MODE: z.enum(['off', 'log', 'enforce']).default('off'),
  ANDROID_PACKAGE_NAME: z.string().default('com.sumt.terminal'),
  PLAY_INTEGRITY_SERVICE_ACCOUNT_JSON: z.string().optional(),
});

export type Env = z.infer<typeof schema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = schema.safeParse(source);
  if (!parsed.success) {
    const msg = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid environment configuration:\n${msg}`);
  }
  return parsed.data;
}
