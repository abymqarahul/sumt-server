/**
 * Creates (or resets the password of) an admin.
 *   node dist/scripts/create-admin.js --email owner@example.com --role SUPERADMIN
 * The password is read from SUMT_ADMIN_PASSWORD or prompted on stdin (never passed as an argument).
 */
import readline from 'node:readline';
import { PrismaClient } from '@prisma/client';
import { hashPassword, validatePasswordStrength } from '../services/admin-auth.service.js';

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function prompt(q: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((res) => rl.question(q, (a) => { rl.close(); res(a); }));
}

async function main() {
  const email = arg('email')?.toLowerCase();
  const role = (arg('role') ?? 'SUPERADMIN').toUpperCase();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error('--email is required');
  if (!['SUPERADMIN', 'ADMIN', 'VIEWER'].includes(role)) throw new Error('--role must be SUPERADMIN, ADMIN or VIEWER');
  const password = process.env.SUMT_ADMIN_PASSWORD ?? (await prompt('Password (min 12 chars): '));
  const weak = validatePasswordStrength(password);
  if (weak) throw new Error(weak);

  const prisma = new PrismaClient();
  const passwordHash = await hashPassword(password);
  const admin = await prisma.admin.upsert({
    where: { email },
    create: { email, passwordHash, role: role as 'SUPERADMIN' },
    update: { passwordHash, role: role as 'SUPERADMIN', disabled: false, failedLogins: 0, lockedUntil: null, tokenVersion: { increment: 1 } },
  });
  await prisma.auditLog.create({ data: { actorType: 'SYSTEM', action: 'admin.cli_upsert', targetType: 'admin', targetId: admin.id, meta: { email, role } } });
  console.log(`Admin ready: ${admin.email} (${admin.role})`);
  await prisma.$disconnect();
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
