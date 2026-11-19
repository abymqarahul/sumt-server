import { execSync } from 'node:child_process';

/** Recreates the dedicated test database schema and applies the real migrations. */
export default function setup() {
  const url = process.env.TEST_DATABASE_URL ?? 'postgresql://sumt:sumt@localhost:5432/sumt_test';
  if (!/test/i.test(url)) throw new Error('Refusing to run tests against a database whose name does not contain "test"');
  process.env.TEST_DATABASE_URL = url;
  execSync(`psql "${url}" -v ON_ERROR_STOP=1 -q -c "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;"`, { stdio: 'inherit' });
  execSync('npx prisma migrate deploy', { stdio: 'inherit', env: { ...process.env, DATABASE_URL: url } });
}
