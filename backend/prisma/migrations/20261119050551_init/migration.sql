-- CreateEnum
CREATE TYPE "InstallationStatus" AS ENUM ('PENDING', 'ACTIVE', 'BLOCKED', 'REVOKED');

-- CreateEnum
CREATE TYPE "LicenseStatus" AS ENUM ('ACTIVE', 'REVOKED', 'TRANSFERRED');

-- CreateEnum
CREATE TYPE "AdminRole" AS ENUM ('SUPERADMIN', 'ADMIN', 'VIEWER');

-- CreateEnum
CREATE TYPE "ActorType" AS ENUM ('ADMIN', 'DEVICE', 'SYSTEM');

-- CreateEnum
CREATE TYPE "ResourceKind" AS ENUM ('FIRMWARE', 'REPAIR_DATA', 'WIRING_DIAGRAM', 'KNOWLEDGE_BASE', 'APP_UPDATE');

-- CreateEnum
CREATE TYPE "ResourceChannel" AS ENUM ('STABLE', 'BETA');

-- CreateTable
CREATE TABLE "installations" (
    "id" UUID NOT NULL,
    "seq" SERIAL NOT NULL,
    "displayId" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "keyFingerprint" TEXT NOT NULL,
    "keyAlgorithm" TEXT NOT NULL DEFAULT 'EC_P256',
    "deviceManufacturer" TEXT,
    "deviceModel" TEXT,
    "deviceSdkInt" INTEGER,
    "appVersionName" TEXT,
    "appVersionCode" INTEGER,
    "integrityVerdict" TEXT,
    "status" "InstallationStatus" NOT NULL DEFAULT 'PENDING',
    "customerName" TEXT,
    "customerPhone" TEXT,
    "notes" TEXT,
    "blockReason" TEXT,
    "failedActivationAttempts" INTEGER NOT NULL DEFAULT 0,
    "activationLockedUntil" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3),
    "lastSeenIp" TEXT,
    "activatedAt" TIMESTAMP(3),
    "blockedAt" TIMESTAMP(3),

    CONSTRAINT "installations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "licenses" (
    "id" UUID NOT NULL,
    "installationId" UUID NOT NULL,
    "status" "LicenseStatus" NOT NULL DEFAULT 'ACTIVE',
    "plan" TEXT NOT NULL DEFAULT 'STANDARD',
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "revokeReason" TEXT,
    "activationKeyId" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "licenses_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "activation_keys" (
    "id" UUID NOT NULL,
    "installationId" UUID NOT NULL,
    "keyHash" TEXT NOT NULL,
    "keyHint" TEXT NOT NULL,
    "licenseDurationDays" INTEGER,
    "plan" TEXT NOT NULL DEFAULT 'STANDARD',
    "createdById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "consumedIp" TEXT,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "activation_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "admins" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "passwordHash" TEXT NOT NULL,
    "role" "AdminRole" NOT NULL DEFAULT 'ADMIN',
    "disabled" BOOLEAN NOT NULL DEFAULT false,
    "failedLogins" INTEGER NOT NULL DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "lastLoginAt" TIMESTAMP(3),
    "tokenVersion" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "admins_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "admin_sessions" (
    "id" UUID NOT NULL,
    "adminId" UUID NOT NULL,
    "refreshTokenHash" TEXT NOT NULL,
    "userAgent" TEXT,
    "ip" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "replacedById" UUID,

    CONSTRAINT "admin_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "used_nonces" (
    "nonce" TEXT NOT NULL,
    "installationId" UUID NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "used_nonces_pkey" PRIMARY KEY ("nonce")
);

-- CreateTable
CREATE TABLE "resources" (
    "id" UUID NOT NULL,
    "kind" "ResourceKind" NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "versionName" TEXT NOT NULL,
    "versionCode" INTEGER NOT NULL,
    "channel" "ResourceChannel" NOT NULL DEFAULT 'STABLE',
    "targetHardware" TEXT,
    "minAppVersionCode" INTEGER,
    "fileName" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL DEFAULT 'application/octet-stream',
    "sizeBytes" BIGINT NOT NULL,
    "sha256" TEXT NOT NULL,
    "storageKey" TEXT NOT NULL,
    "releaseNotes" TEXT,
    "published" BOOLEAN NOT NULL DEFAULT false,
    "publishedAt" TIMESTAMP(3),
    "uploadedById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "resources_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" BIGSERIAL NOT NULL,
    "actorType" "ActorType" NOT NULL,
    "actorId" TEXT,
    "action" TEXT NOT NULL,
    "targetType" TEXT,
    "targetId" TEXT,
    "ip" TEXT,
    "meta" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "installations_seq_key" ON "installations"("seq");

-- CreateIndex
CREATE UNIQUE INDEX "installations_displayId_key" ON "installations"("displayId");

-- CreateIndex
CREATE UNIQUE INDEX "installations_keyFingerprint_key" ON "installations"("keyFingerprint");

-- CreateIndex
CREATE INDEX "installations_status_idx" ON "installations"("status");

-- CreateIndex
CREATE INDEX "installations_createdAt_idx" ON "installations"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "licenses_activationKeyId_key" ON "licenses"("activationKeyId");

-- CreateIndex
CREATE INDEX "licenses_installationId_status_idx" ON "licenses"("installationId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "activation_keys_keyHash_key" ON "activation_keys"("keyHash");

-- CreateIndex
CREATE INDEX "activation_keys_installationId_idx" ON "activation_keys"("installationId");

-- CreateIndex
CREATE UNIQUE INDEX "admins_email_key" ON "admins"("email");

-- CreateIndex
CREATE UNIQUE INDEX "admin_sessions_refreshTokenHash_key" ON "admin_sessions"("refreshTokenHash");

-- CreateIndex
CREATE INDEX "admin_sessions_adminId_idx" ON "admin_sessions"("adminId");

-- CreateIndex
CREATE INDEX "used_nonces_expiresAt_idx" ON "used_nonces"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "resources_storageKey_key" ON "resources"("storageKey");

-- CreateIndex
CREATE INDEX "resources_kind_published_idx" ON "resources"("kind", "published");

-- CreateIndex
CREATE UNIQUE INDEX "resources_slug_versionCode_channel_key" ON "resources"("slug", "versionCode", "channel");

-- CreateIndex
CREATE INDEX "audit_logs_createdAt_idx" ON "audit_logs"("createdAt");

-- CreateIndex
CREATE INDEX "audit_logs_targetType_targetId_idx" ON "audit_logs"("targetType", "targetId");

-- CreateIndex
CREATE INDEX "audit_logs_action_idx" ON "audit_logs"("action");

-- AddForeignKey
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_installationId_fkey" FOREIGN KEY ("installationId") REFERENCES "installations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_activationKeyId_fkey" FOREIGN KEY ("activationKeyId") REFERENCES "activation_keys"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "activation_keys" ADD CONSTRAINT "activation_keys_installationId_fkey" FOREIGN KEY ("installationId") REFERENCES "installations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "activation_keys" ADD CONSTRAINT "activation_keys_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "admins"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "admin_sessions" ADD CONSTRAINT "admin_sessions_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "admins"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "resources" ADD CONSTRAINT "resources_uploadedById_fkey" FOREIGN KEY ("uploadedById") REFERENCES "admins"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Human-facing installation numbers start at SUMT-10001
ALTER SEQUENCE "installations_seq_seq" RESTART WITH 10001;
