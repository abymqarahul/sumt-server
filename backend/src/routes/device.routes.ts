import type { FastifyInstance } from 'fastify';
import { deviceAuth } from '../middleware/device-auth.js';
import { consumeSchema, deviceResourceQuery } from '../validators/schemas.js';
import { consumeKey } from '../services/activation.service.js';
import { buildLicenseView, effectiveStatus, getActiveLicense } from '../services/license.service.js';
import { serializeResource } from '../services/resource.service.js';
import { signTicket } from '../security/crypto.js';
import { forbidden, notFound } from '../utils/errors.js';
import type { TicketPayload } from './public.routes.js';

export async function deviceRoutes(app: FastifyInstance) {
  const ctx = app.ctx;
  app.addHook('preHandler', deviceAuth);

  app.post(
    '/activations/consume',
    { config: { rateLimit: { max: ctx.env.RATE_LIMIT_AUTH_PER_MIN, timeWindow: '1 minute' } } },
    async (req) => {
      const body = consumeSchema.parse(req.body);
      const { license, installation } = await consumeKey(ctx, req.installation!, body.activationKey, req.ip);
      return buildLicenseView(ctx, installation, license);
    },
  );

  app.get('/licenses/verify', async (req) => {
    const inst = await ctx.prisma.installation.update({
      where: { id: req.installation!.id },
      data: { lastSeenAt: new Date(), lastSeenIp: req.ip },
    });
    const license = await getActiveLicense(ctx.prisma, inst.id);
    return buildLicenseView(ctx, inst, license);
  });

  /** Latest published version of each resource (firmware, repair data, diagrams, KB, app updates). */
  app.get('/resources', async (req) => {
    const q = deviceResourceQuery.parse(req.query);
    const inst = req.installation!;
    const license = await getActiveLicense(ctx.prisma, inst.id);
    if (effectiveStatus(inst, license) !== 'ACTIVE') throw forbidden('LICENSE_REQUIRED', 'An active licence is required');
    const channels = q.channel === 'BETA' ? (['STABLE', 'BETA'] as const) : (['STABLE'] as const);
    const rows = await ctx.prisma.resource.findMany({
      where: {
        published: true,
        channel: { in: [...channels] },
        ...(q.kind ? { kind: q.kind } : {}),
        ...(inst.appVersionCode != null
          ? { OR: [{ minAppVersionCode: null }, { minAppVersionCode: { lte: inst.appVersionCode } }] }
          : {}),
      },
      orderBy: [{ slug: 'asc' }, { versionCode: 'desc' }],
    });
    const latest = new Map<string, (typeof rows)[number]>();
    for (const r of rows) if (!latest.has(r.slug)) latest.set(r.slug, r);
    return { items: [...latest.values()].map((r) => serializeResource(r)), serverTime: new Date().toISOString() };
  });

  app.post<{ Params: { id: string } }>('/resources/:id/ticket', async (req) => {
    const inst = req.installation!;
    const license = await getActiveLicense(ctx.prisma, inst.id);
    if (effectiveStatus(inst, license) !== 'ACTIVE') throw forbidden('LICENSE_REQUIRED', 'An active licence is required');
    const r = await ctx.prisma.resource.findFirst({ where: { id: req.params.id, published: true } }).catch(() => null);
    if (!r) throw notFound('RESOURCE_NOT_FOUND', 'Resource is not available');
    const exp = Math.floor(Date.now() / 1000) + ctx.env.DOWNLOAD_TICKET_TTL_SEC;
    const ticket = signTicket({ rid: r.id, iid: inst.id, exp } satisfies TicketPayload, ctx.env.DOWNLOAD_TICKET_SECRET);
    const path = `/api/v1/resources/download/${ticket}`;
    return {
      url: ctx.env.PUBLIC_BASE_URL ? `${ctx.env.PUBLIC_BASE_URL.replace(/\/$/, '')}${path}` : path,
      path,
      expiresAt: new Date(exp * 1000).toISOString(),
      sha256: r.sha256,
      sizeBytes: Number(r.sizeBytes),
    };
  });
}
