import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { Readable } from 'node:stream';

/**
 * File storage on a local directory. On Railway, mount a Volume at /data and set
 * STORAGE_DIR=/data/resources so uploads survive redeploys.
 */
export class LocalStorage {
  constructor(private readonly root: string) {}

  async init(): Promise<void> {
    await fsp.mkdir(path.join(this.root, '.tmp'), { recursive: true });
  }

  private resolve(key: string): string {
    if (!/^[0-9a-f-]{36}$/.test(key)) throw new Error('Invalid storage key');
    return path.join(this.root, key);
  }

  /** Streams to a temp file while computing SHA-256 and size; enforces a byte limit. */
  async writeTemp(stream: Readable, maxBytes: number): Promise<{ tempPath: string; sha256: string; size: number }> {
    const tempPath = path.join(this.root, '.tmp', crypto.randomUUID());
    const hash = crypto.createHash('sha256');
    let size = 0;
    const meter = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        size += chunk.length;
        if (size > maxBytes) return cb(new Error('FILE_TOO_LARGE'));
        hash.update(chunk);
        cb(null, chunk);
      },
    });
    try {
      await pipeline(stream, meter, fs.createWriteStream(tempPath, { flags: 'wx' }));
    } catch (err) {
      await fsp.rm(tempPath, { force: true });
      throw err;
    }
    return { tempPath, sha256: hash.digest('hex'), size };
  }

  async commit(tempPath: string, key: string): Promise<void> {
    await fsp.rename(tempPath, this.resolve(key));
  }

  async discard(tempPath: string): Promise<void> {
    await fsp.rm(tempPath, { force: true });
  }

  async remove(key: string): Promise<void> {
    await fsp.rm(this.resolve(key), { force: true });
  }

  async stat(key: string): Promise<fs.Stats | null> {
    try {
      return await fsp.stat(this.resolve(key));
    } catch {
      return null;
    }
  }

  createReadStream(key: string, range?: { start: number; end: number }) {
    return fs.createReadStream(this.resolve(key), range);
  }
}
