import type { Resource } from '@prisma/client';

export function serializeResource(r: Resource, opts: { admin?: boolean } = {}) {
  const base = {
    id: r.id,
    kind: r.kind,
    slug: r.slug,
    name: r.name,
    versionName: r.versionName,
    versionCode: r.versionCode,
    channel: r.channel,
    targetHardware: r.targetHardware,
    minAppVersionCode: r.minAppVersionCode,
    fileName: r.fileName,
    mimeType: r.mimeType,
    sizeBytes: Number(r.sizeBytes),
    sha256: r.sha256,
    releaseNotes: r.releaseNotes,
    publishedAt: r.publishedAt,
  };
  if (!opts.admin) return base;
  return { ...base, published: r.published, uploadedById: r.uploadedById, createdAt: r.createdAt, updatedAt: r.updatedAt };
}

export function safeFileName(name: string): string {
  const base = name.replace(/^.*[\\/]/, '').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
  return base || 'file.bin';
}

/** Parses a single "bytes=start-end" range. Returns null for unsatisfiable/unsupported ranges. */
export function parseRange(header: string | undefined, size: number): { start: number; end: number } | null | undefined {
  if (!header) return undefined;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === '' && m[2] === '')) return null;
  let start: number;
  let end: number;
  if (m[1] === '') {
    const suffix = Number(m[2]);
    if (suffix === 0) return null;
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === '' ? size - 1 : Math.min(Number(m[2]), size - 1);
  }
  if (start > end || start >= size) return null;
  return { start, end };
}
