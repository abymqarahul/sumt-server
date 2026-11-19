import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Prisma } from '@prisma/client';
import crypto from 'node:crypto';
import {
  auditQuery,
  changePasswordSchema,
  createAdminSchema,
  generateKeySchema,
  listInstallationsSchema,
  loginSchema,
  pageQuery,
  reasonSchema,
  refreshSchema,
  resourceMetaSchema,
  transferSchema,
  updateAdminSchema,
  updateInstallationSchema,
  updateLicenseSchema,
  updateResourceSchema,
} from '../validators/schemas.js';
import {
  hashPassword,
  login,
  logout,
  publicAdmin,
  refresh,
  requireAdmin,
  revokeAllSessions,
  validatePasswordStrength,
} from '../services/admin-auth.service.js';
import argon2 from 'argon2';
import { resolveInstallation } from '../services/installation.service.js';
import { generateKey } from '../services/activation.service.js';
import { effectiveStatus, getActiveLicense } from '../services/license.service.js';
import { audit } from '../services/audit.service.js';
import { safeFileName, serializeResource } from '../services/resource.service.js';
import { AppError, badRequest, conflict, forbidden, notFound } from '../utils/errors.js';
import { isUniqueViolation } from '../database/prisma.js';

export async function adminRoutes(app: FastifyInstance) {
  const ctx = app.ctx;
  const { prisma } = ctx;
  const viewer = { preHandler: requireAdmin('VIEWER') };
  const admin = { preHandler: requireAdmin('ADMIN') };
  const superadmin = { preHandler: requireAdmin('SUPERADMIN') };
  const actor = (req: FastifyRequest) => ({ actorType: 'ADMIN' as const, actorId: req.admin!.id, ip: req.ip });

  // ---------------- Auth ----------------
  app.post('/login', { config: { rateLimit: { max: ctx.env.RATE_LIMIT_AUTH_PER_MIN, timeWindow: '1 minute' } } }, async (req) => {
    const b = loginSchema.parse(req.body);
    return login(ctx, b.email, b.password, req);
  });

  app.post('/refresh', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req) => {
    const b = refreshSchema.parse(req.body);
    return refresh(ctx, b.refreshToken, req);
  });

  app.post('/logout', async (req) => {
    const b = refreshSchema.parse(req.body);
    await logout(ctx, b.refreshToken);
    return { ok: true };
  });

  app.get('/me', viewer, async (req) => publicAdmin(req.admin!));

  app.post('/me/password', { ...viewer, config: { rateLimit: { max: 5, timeWindow: '1 minute' } } }, async (req) => {
    const b = changePasswordSchema.parse(req.body);
    const me = req.admin!;
    if (!(await argon2.verify(me.passwordHash, b.currentPassword).catch(() => false))) {
      throw badRequest('INVALID_CREDENTIALS', 'Current password is incorrect');
    }
    const weak = validatePasswordStrength(b.newPassword);
    if (weak) throw badRequest('WEAK_PASSWORD', weak);
    await prisma.admin.update({ where: { id: me.id }, data: { passwordHash: await hashPassword(b.newPassword) } });
    await revokeAllSessions(prisma, me.id);
    await audit(prisma, { ...actor(req), action: 'admin.password_change', targetType: 'admin', targetId: me.id });
    return { ok: true, message: 'Password changed. Please log in again on all devices.' };
  });

  // ---------------- Dashboard ----------------
  app.get('/dashboard', viewer, async () => {
    const now = new Date();
    const soon = new Date(now.getTime() + 7 * 86400_000);
    const dayAgo = new Date(now.getTime() - 86400_000);
    const [byStatus, expired, expiringSoon, last24h, pendingKeys, resources] = await Promise.all([
      prisma.installation.groupBy({ by: ['status'], _count: { _all: true } }),
      prisma.license.count({ where: { status: 'ACTIVE', expiresAt: { lte: now }, installation: { status: { not: 'BLOCKED' } } } }),
      prisma.license.count({ where: { status: 'ACTIVE', expiresAt: { gt: now, lte: soon } } }),
      prisma.installation.count({ where: { createdAt: { gte: dayAgo } } }),
      prisma.activationKey.count({ where: { consumedAt: null, revokedAt: null, expiresAt: { gt: now } } }),
      prisma.resource.count({ where: { published: true } }),
    ]);
    const counts = Object.fromEntries(byStatus.map((s) => [s.status, s._count._all])) as Record<string, number>;
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    return {
      totalInstallations: total,
      pending: counts.PENDING ?? 0,
      active: Math.max(0, (counts.ACTIVE ?? 0) - expired),
      expired,
      blocked: counts.BLOCKED ?? 0,
      revoked: counts.REVOKED ?? 0,
      expiringIn7Days: expiringSoon,
      newLast24h: last24h,
      outstandingKeys: pendingKeys,
      publishedResources: resources,
      serverTime: now.toISOString(),
    };
  });

  // ---------------- Installations ----------------
  app.get('/installations', viewer, async (req) => {
    const q = listInstallationsSchema.parse(req.query);
    const now = new Date();
    const where: Prisma.InstallationWhereInput = {};
    if (q.status === 'EXPIRED') {
      where.status = 'ACTIVE';
      where.licenses = { some: { status: 'ACTIVE', expiresAt: { lte: now } } };
    } else if (q.status === 'ACTIVE') {
      where.status = 'ACTIVE';
      where.licenses = { some: { status: 'ACTIVE', OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] } };
    } else if (q.status) {
      where.status = q.status;
    }
    if (q.q) {
      const m = /^(?:SUMT-?)?(\d{1,10})$/i.exec(q.q);
      where.OR = [
        ...(m ? [{ seq: Number(m[1]) }] : []),
        { displayId: { contains: q.q, mode: 'insensitive' } },
        { customerName: { contains: q.q, mode: 'insensitive' } },
        { customerPhone: { contains: q.q } },
        { deviceModel: { contains: q.q, mode: 'insensitive' } },
        { notes: { contains: q.q, mode: 'insensitive' } },
      ];
    }
    const [total, rows] = await Promise.all([
      prisma.installation.count({ where }),
      prisma.installation.findMany({
        where,
        orderBy: { [q.sort]: q.order },
        skip: (q.page - 1) * q.pageSize,
        take: q.pageSize,
        include: { licenses: { where: { status: 'ACTIVE' }, orderBy: { issuedAt: 'desc' }, take: 1 } },
      }),
    ]);
    return {
      page: q.page,
      pageSize: q.pageSize,
      total,
      items: rows.map((r) => serializeInstallation(r, r.licenses[0] ?? null)),
    };
  });

  app.get<{ Params: { id: string } }>('/installations/:id', viewer, async (req) => {
    const inst = await resolveInstallation(prisma, req.params.id);
    const [licenses, keys, logs] = await Promise.all([
      prisma.license.findMany({ where: { installationId: inst.id }, orderBy: { issuedAt: 'desc' } }),
      prisma.activationKey.findMany({
        where: { installationId: inst.id },
        orderBy: { createdAt: 'desc' },
        select: { id: true, keyHint: true, licenseDurationDays: true, plan: true, createdAt: true, expiresAt: true, consumedAt: true, revokedAt: true, createdBy: { select: { email: true } } },
      }),
      prisma.auditLog.findMany({ where: { targetType: 'installation', targetId: inst.id }, orderBy: { createdAt: 'desc' }, take: 100 }),
    ]);
    const active = licenses.find((l) => l.status === 'ACTIVE') ?? null;
    return {
      ...serializeInstallation(inst, active),
      keyFingerprint: inst.keyFingerprint,
      integrityVerdict: inst.integrityVerdict,
      failedActivationAttempts: inst.failedActivationAttempts,
      activationLockedUntil: inst.activationLockedUntil,
      lastSeenIp: inst.lastSeenIp,
      licenses,
      activationKeys: keys.map((k) => ({
        ...k,
        state: k.consumedAt ? 'USED' : k.revokedAt ? 'REVOKED' : k.expiresAt < new Date() ? 'EXPIRED' : 'UNUSED',
        createdBy: k.createdBy?.email ?? null,
      })),
      history: logs.map(serializeAudit),
    };
  });

  app.patch<{ Params: { id: string } }>('/installations/:id', admin, async (req) => {
    const b = updateInstallationSchema.parse(req.body);
    const inst = await resolveInstallation(prisma, req.params.id);
    const updated = await prisma.installation.update({ where: { id: inst.id }, data: b });
    await audit(prisma, { ...actor(req), action: 'installation.update', targetType: 'installation', targetId: inst.id, meta: b });
    return serializeInstallation(updated, await getActiveLicense(prisma, inst.id));
  });

  app.post<{ Params: { id: string } }>('/installations/:id/block', admin, async (req) => {
    const b = reasonSchema.parse(req.body ?? {});
    const inst = await resolveInstallation(prisma, req.params.id);
    const now = new Date();
    const updated = await prisma.$transaction(async (tx) => {
      await tx.activationKey.updateMany({ where: { installationId: inst.id, consumedAt: null, revokedAt: null }, data: { revokedAt: now } });
      const u = await tx.installation.update({ where: { id: inst.id }, data: { status: 'BLOCKED', blockedAt: now, blockReason: b.reason ?? null } });
      await audit(tx, { ...actor(req), action: 'installation.block', targetType: 'installation', targetId: inst.id, meta: { reason: b.reason ?? null } });
      return u;
    });
    return serializeInstallation(updated, await getActiveLicense(prisma, inst.id));
  });

  app.post<{ Params: { id: string } }>('/installations/:id/unblock', admin, async (req) => {
    const inst = await resolveInstallation(prisma, req.params.id);
    if (inst.status !== 'BLOCKED') throw conflict('NOT_BLOCKED', 'Installation is not blocked');
    const license = await getActiveLicense(prisma, inst.id);
    const updated = await prisma.installation.update({
      where: { id: inst.id },
      data: { status: license ? 'ACTIVE' : 'PENDING', blockedAt: null, blockReason: null },
    });
    await audit(prisma, { ...actor(req), action: 'installation.unblock', targetType: 'installation', targetId: inst.id });
    return serializeInstallation(updated, license);
  });

  /** Owner-controlled reset: revokes licences and keys; installation returns to PENDING. */
  app.post<{ Params: { id: string } }>('/installations/:id/reset', admin, async (req) => {
    const b = reasonSchema.parse(req.body ?? {});
    const inst = await resolveInstallation(prisma, req.params.id);
    const now = new Date();
    const updated = await prisma.$transaction(async (tx) => {
      const lic = await tx.license.updateMany({
        where: { installationId: inst.id, status: 'ACTIVE' },
        data: { status: 'REVOKED', revokedAt: now, revokeReason: b.reason ?? 'Activation reset by admin' },
      });
      const keys = await tx.activationKey.updateMany({ where: { installationId: inst.id, consumedAt: null, revokedAt: null }, data: { revokedAt: now } });
      const u = await tx.installation.update({
        where: { id: inst.id },
        data: { status: 'PENDING', activatedAt: null, blockedAt: null, blockReason: null, failedActivationAttempts: 0, activationLockedUntil: null },
      });
      await audit(tx, { ...actor(req), action: 'installation.reset', targetType: 'installation', targetId: inst.id, meta: { licensesRevoked: lic.count, keysRevoked: keys.count, reason: b.reason ?? null } });
      return u;
    });
    return serializeInstallation(updated, null);
  });

  /** Reinstall recovery: move the remaining licence from an old installation to its replacement. */
  app.post<{ Params: { id: string } }>('/installations/:id/transfer', admin, async (req) => {
    const b = transferSchema.parse(req.body);
    const from = await resolveInstallation(prisma, req.params.id);
    const to = await resolveInstallation(prisma, b.toInstallationId);
    if (from.id === to.id) throw badRequest('SAME_INSTALLATION', 'Source and target are the same');
    if (to.status === 'BLOCKED') throw conflict('INSTALLATION_BLOCKED', 'Target installation is blocked');
    const now = new Date();
    const result = await prisma.$transaction(async (tx) => {
      const src = await tx.license.findFirst({ where: { installationId: from.id, status: 'ACTIVE' }, orderBy: { issuedAt: 'desc' } });
      if (!src) throw conflict('NO_ACTIVE_LICENSE', 'Source installation has no active licence to transfer');
      if (src.expiresAt && src.expiresAt <= now) throw conflict('LICENSE_EXPIRED', 'Source licence has already expired');
      const targetActive = await tx.license.count({ where: { installationId: to.id, status: 'ACTIVE' } });
      if (targetActive > 0) throw conflict('TARGET_ALREADY_LICENSED', 'Target installation already has an active licence');
      await tx.license.update({ where: { id: src.id }, data: { status: 'TRANSFERRED', revokedAt: now, revokeReason: `Transferred to ${to.displayId}` } });
      const lic = await tx.license.create({ data: { installationId: to.id, plan: src.plan, expiresAt: src.expiresAt } });
      await tx.installation.update({ where: { id: from.id }, data: { status: 'REVOKED' } });
      await tx.activationKey.updateMany({ where: { installationId: { in: [from.id, to.id] }, consumedAt: null, revokedAt: null }, data: { revokedAt: now } });
      const t = await tx.installation.update({ where: { id: to.id }, data: { status: 'ACTIVE', activatedAt: now } });
      const meta = { from: from.displayId, to: to.displayId, licenseId: lic.id, reason: b.reason ?? null };
      await audit(tx, { ...actor(req), action: 'license.transfer_out', targetType: 'installation', targetId: from.id, meta });
      await audit(tx, { ...actor(req), action: 'license.transfer_in', targetType: 'installation', targetId: to.id, meta });
      return { t, lic };
    });
    return serializeInstallation(result.t, result.lic);
  });

  // ---------------- Activation keys ----------------
  app.post('/activations/generate', admin, async (req) => {
    const b = generateKeySchema.parse(req.body);
    const inst = await resolveInstallation(prisma, b.installationId);
    return generateKey(ctx, {
      installation: inst,
      admin: req.admin!,
      licenseDays: b.licenseDays ?? null,
      keyValidHours: b.keyValidHours ?? ctx.env.DEFAULT_KEY_VALID_HOURS,
      plan: b.plan ?? 'STANDARD',
      ip: req.ip,
    });
  });

  app.get('/activations/history', viewer, async (req) => {
    const q = pageQuery.extend({ installationId: generateKeySchema.shape.installationId.optional() }).parse(req.query);
    const where: Prisma.ActivationKeyWhereInput = {};
    if (q.installationId) where.installationId = (await resolveInstallation(prisma, q.installationId)).id;
    const [total, rows] = await Promise.all([
      prisma.activationKey.count({ where }),
      prisma.activationKey.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (q.page - 1) * q.pageSize,
        take: q.pageSize,
        select: {
          id: true, keyHint: true, licenseDurationDays: true, plan: true, createdAt: true, expiresAt: true, consumedAt: true, revokedAt: true,
          installation: { select: { id: true, displayId: true } }, createdBy: { select: { email: true } },
        },
      }),
    ]);
    const now = new Date();
    return {
      page: q.page, pageSize: q.pageSize, total,
      items: rows.map((k) => ({ ...k, createdBy: k.createdBy?.email ?? null, state: k.consumedAt ? 'USED' : k.revokedAt ? 'REVOKED' : k.expiresAt < now ? 'EXPIRED' : 'UNUSED' })),
    };
  });

  app.post<{ Params: { id: string } }>('/activations/:id/revoke', admin, async (req) => {
    const key = await prisma.activationKey.findUnique({ where: { id: req.params.id } }).catch(() => null);
    if (!key) throw notFound('KEY_NOT_FOUND', 'Activation key not found');
    if (key.consumedAt) throw conflict('KEY_ALREADY_USED', 'Key already used; revoke the licence instead');
    await prisma.activationKey.update({ where: { id: key.id }, data: { revokedAt: key.revokedAt ?? new Date() } });
    await audit(prisma, { ...actor(req), action: 'activation_key.revoke', targetType: 'installation', targetId: key.installationId, meta: { keyId: key.id } });
    return { ok: true };
  });

  // ---------------- Licences ----------------
  app.post<{ Params: { id: string } }>('/licenses/:id/revoke', admin, async (req) => {
    const b = reasonSchema.parse(req.body ?? {});
    const lic = await prisma.license.findUnique({ where: { id: req.params.id } }).catch(() => null);
    if (!lic) throw notFound('LICENSE_NOT_FOUND', 'Licence not found');
    if (lic.status !== 'ACTIVE') throw conflict('LICENSE_NOT_ACTIVE', 'Licence is not active');
    const now = new Date();
    await prisma.$transaction(async (tx) => {
      await tx.license.update({ where: { id: lic.id }, data: { status: 'REVOKED', revokedAt: now, revokeReason: b.reason ?? 'Revoked by admin' } });
      const others = await tx.license.count({ where: { installationId: lic.installationId, status: 'ACTIVE' } });
      const inst = await tx.installation.findUniqueOrThrow({ where: { id: lic.installationId } });
      if (others === 0 && inst.status !== 'BLOCKED') await tx.installation.update({ where: { id: inst.id }, data: { status: 'REVOKED' } });
      await audit(tx, { ...actor(req), action: 'license.revoke', targetType: 'installation', targetId: lic.installationId, meta: { licenseId: lic.id, reason: b.reason ?? null } });
    });
    return prisma.license.findUnique({ where: { id: lic.id } });
  });

  /** Set or extend expiry. `expiresAt: null` makes it lifetime. */
  app.patch<{ Params: { id: string } }>('/licenses/:id', admin, async (req) => {
    const b = updateLicenseSchema.parse(req.body);
    const lic = await prisma.license.findUnique({ where: { id: req.params.id } }).catch(() => null);
    if (!lic) throw notFound('LICENSE_NOT_FOUND', 'Licence not found');
    if (lic.status !== 'ACTIVE') throw conflict('LICENSE_NOT_ACTIVE', 'Only active licences can be changed');
    const expiresAt = b.expiresAt ? new Date(b.expiresAt) : null;
    const updated = await prisma.license.update({ where: { id: lic.id }, data: { expiresAt } });
    await audit(prisma, {
      ...actor(req), action: 'license.update_expiry', targetType: 'installation', targetId: lic.installationId,
      meta: { licenseId: lic.id, from: lic.expiresAt?.toISOString() ?? null, to: expiresAt?.toISOString() ?? null },
    });
    return updated;
  });

  // ---------------- Resources (firmware / OTA) ----------------
  app.get('/resources', viewer, async (req) => {
    const q = pageQuery.extend({ kind: resourceMetaSchema.shape.kind.optional(), slug: resourceMetaSchema.shape.slug.optional() }).parse(req.query);
    const where: Prisma.ResourceWhereInput = { ...(q.kind ? { kind: q.kind } : {}), ...(q.slug ? { slug: q.slug } : {}) };
    const [total, rows] = await Promise.all([
      prisma.resource.count({ where }),
      prisma.resource.findMany({ where, orderBy: [{ createdAt: 'desc' }], skip: (q.page - 1) * q.pageSize, take: q.pageSize }),
    ]);
    return { page: q.page, pageSize: q.pageSize, total, items: rows.map((r) => serializeResource(r, { admin: true })) };
  });

  /** multipart/form-data: metadata fields + one `file` part. SHA-256 and size are computed server-side. */
  app.post('/resources', admin, async (req, reply) => {
    if (!req.isMultipart()) throw badRequest('MULTIPART_REQUIRED', 'Use multipart/form-data');
    const fields: Record<string, string> = {};
    let file: { tempPath: string; sha256: string; size: number; fileName: string; mime: string } | null = null;
    try {
      for await (const part of req.parts()) {
        if (part.type === 'file') {
          if (file) {
            part.file.resume();
            throw badRequest('ONE_FILE_ONLY', 'Upload exactly one file');
          }
          try {
            const w = await ctx.storage.writeTemp(part.file, ctx.env.MAX_UPLOAD_MB * 1024 * 1024);
            if (part.file.truncated) throw new Error('FILE_TOO_LARGE');
            file = { ...w, fileName: safeFileName(part.filename), mime: part.mimetype || 'application/octet-stream' };
          } catch (e) {
            if ((e as Error).message === 'FILE_TOO_LARGE') throw new AppError(413, 'FILE_TOO_LARGE', `File exceeds ${ctx.env.MAX_UPLOAD_MB} MB`);
            throw e;
          }
        } else {
          fields[part.fieldname] = String(part.value);
        }
      }
      if (!file) throw badRequest('FILE_REQUIRED', 'A file part named "file" is required');
      if (file.size === 0) throw badRequest('EMPTY_FILE', 'File is empty');
      const meta = resourceMetaSchema.parse(fields);
      if (fields.sha256 && fields.sha256.toLowerCase() !== file.sha256) {
        throw badRequest('CHECKSUM_MISMATCH', `Uploaded file SHA-256 ${file.sha256} does not match the expected value`);
      }
      const storageKey = crypto.randomUUID();
      let created;
      try {
        created = await prisma.resource.create({
          data: {
            kind: meta.kind, slug: meta.slug, name: meta.name, versionName: meta.versionName, versionCode: meta.versionCode,
            channel: meta.channel, targetHardware: meta.targetHardware ?? null, minAppVersionCode: meta.minAppVersionCode ?? null,
            releaseNotes: meta.releaseNotes ?? null, fileName: file.fileName, mimeType: file.mime, sizeBytes: BigInt(file.size),
            sha256: file.sha256, storageKey, published: meta.publish, publishedAt: meta.publish ? new Date() : null, uploadedById: req.admin!.id,
          },
        });
      } catch (e) {
        if (isUniqueViolation(e)) throw conflict('VERSION_EXISTS', 'This slug already has that versionCode on this channel');
        throw e;
      }
      await ctx.storage.commit(file.tempPath, storageKey);
      file = null;
      await audit(prisma, { ...actor(req), action: 'resource.upload', targetType: 'resource', targetId: created.id, meta: { slug: created.slug, versionCode: created.versionCode, sha256: created.sha256, published: created.published } });
      return reply.code(201).send(serializeResource(created, { admin: true }));
    } finally {
      if (file) await ctx.storage.discard(file.tempPath);
    }
  });

  app.patch<{ Params: { id: string } }>('/resources/:id', admin, async (req) => {
    const b = updateResourceSchema.parse(req.body);
    const r = await prisma.resource.findUnique({ where: { id: req.params.id } }).catch(() => null);
    if (!r) throw notFound('RESOURCE_NOT_FOUND', 'Resource not found');
    const data: Prisma.ResourceUpdateInput = { ...b };
    if (b.published === true && !r.published) data.publishedAt = new Date();
    const u = await prisma.resource.update({ where: { id: r.id }, data });
    await audit(prisma, { ...actor(req), action: b.published === undefined ? 'resource.update' : b.published ? 'resource.publish' : 'resource.unpublish', targetType: 'resource', targetId: r.id, meta: b });
    return serializeResource(u, { admin: true });
  });

  app.delete<{ Params: { id: string } }>('/resources/:id', superadmin, async (req) => {
    const r = await prisma.resource.findUnique({ where: { id: req.params.id } }).catch(() => null);
    if (!r) throw notFound('RESOURCE_NOT_FOUND', 'Resource not found');
    await prisma.resource.delete({ where: { id: r.id } });
    await ctx.storage.remove(r.storageKey);
    await audit(prisma, { ...actor(req), action: 'resource.delete', targetType: 'resource', targetId: r.id, meta: { slug: r.slug, versionCode: r.versionCode, sha256: r.sha256 } });
    return { ok: true };
  });

  // ---------------- Admin users ----------------
  app.get('/admins', superadmin, async () => (await prisma.admin.findMany({ orderBy: { createdAt: 'asc' } })).map(publicAdmin));

  app.post('/admins', superadmin, async (req, reply) => {
    const b = createAdminSchema.parse(req.body);
    const weak = validatePasswordStrength(b.password);
    if (weak) throw badRequest('WEAK_PASSWORD', weak);
    try {
      const a = await prisma.admin.create({ data: { email: b.email.toLowerCase(), name: b.name ?? null, role: b.role, passwordHash: await hashPassword(b.password) } });
      await audit(prisma, { ...actor(req), action: 'admin.create', targetType: 'admin', targetId: a.id, meta: { email: a.email, role: a.role } });
      return reply.code(201).send(publicAdmin(a));
    } catch (e) {
      if (isUniqueViolation(e)) throw conflict('EMAIL_EXISTS', 'An admin with this email already exists');
      throw e;
    }
  });

  app.patch<{ Params: { id: string } }>('/admins/:id', superadmin, async (req) => {
    const b = updateAdminSchema.parse(req.body);
    const target = await prisma.admin.findUnique({ where: { id: req.params.id } }).catch(() => null);
    if (!target) throw notFound('ADMIN_NOT_FOUND', 'Admin not found');
    if (target.id === req.admin!.id && (b.disabled === true || (b.role && b.role !== 'SUPERADMIN'))) {
      throw forbidden('SELF_LOCKOUT', 'You cannot disable or demote yourself');
    }
    const a = await prisma.admin.update({ where: { id: target.id }, data: b });
    if (b.disabled || b.role) await revokeAllSessions(prisma, target.id);
    await audit(prisma, { ...actor(req), action: 'admin.update', targetType: 'admin', targetId: a.id, meta: b });
    return publicAdmin(a);
  });

  // ---------------- Audit ----------------
  app.get('/audit-logs', viewer, async (req) => {
    const q = auditQuery.parse(req.query);
    const where: Prisma.AuditLogWhereInput = {
      ...(q.action ? { action: { startsWith: q.action } } : {}),
      ...(q.targetId ? { targetId: q.targetId } : {}),
      ...(q.actorId ? { actorId: q.actorId } : {}),
    };
    const [total, rows] = await Promise.all([
      prisma.auditLog.count({ where }),
      prisma.auditLog.findMany({ where, orderBy: { createdAt: 'desc' }, skip: (q.page - 1) * q.pageSize, take: q.pageSize }),
    ]);
    return { page: q.page, pageSize: q.pageSize, total, items: rows.map(serializeAudit) };
  });
}

function serializeInstallation(
  i: import('@prisma/client').Installation,
  license: import('@prisma/client').License | null,
) {
  return {
    id: i.id,
    displayId: i.displayId,
    status: i.status,
    effectiveStatus: effectiveStatus(i, license),
    customerName: i.customerName,
    customerPhone: i.customerPhone,
    notes: i.notes,
    device: { manufacturer: i.deviceManufacturer, model: i.deviceModel, sdkInt: i.deviceSdkInt },
    app: { versionName: i.appVersionName, versionCode: i.appVersionCode },
    blockReason: i.blockReason,
    createdAt: i.createdAt,
    activatedAt: i.activatedAt,
    blockedAt: i.blockedAt,
    lastSeenAt: i.lastSeenAt,
    license: license ? { id: license.id, plan: license.plan, issuedAt: license.issuedAt, expiresAt: license.expiresAt } : null,
  };
}

function serializeAudit(l: import('@prisma/client').AuditLog) {
  return { ...l, id: l.id.toString() };
}
