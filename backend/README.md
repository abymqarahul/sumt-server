# SUMT Backend

Licensing, device-bound activation, admin management and firmware/resource distribution for **SUMT — Smart Universal Mobile Terminal**.

Stack: Node 22 · TypeScript · Fastify 5 · Prisma 6 · PostgreSQL 16 · argon2id · ES256 licence tokens.

```
src/
  config/env.ts            single configuration layer (validated with zod)
  app.ts / server.ts       Fastify app, error handling, rate limit, HTTPS enforcement
  routes/                  public · device (signed) · admin (JWT + roles)
  services/                activation · license · installation · admin-auth · audit · integrity · resource · nonce
  middleware/device-auth   Keystore-signature verification + replay protection
  security/crypto.ts       key generation/hashing, signatures, licence tokens, tickets
  storage/local.ts         streaming uploads with SHA-256 (Railway Volume)
  scripts/                 generate-keys, create-admin
prisma/                    schema + migrations
tests/                     vitest suites against a real PostgreSQL
docs/                      API.md, DEPLOY_RAILWAY.md
```

## Local development
```bash
npm ci
cp .env.example .env        # fill DATABASE_URL + secrets (npm run build && npm run keys:generate)
npx prisma migrate deploy
npm run dev
```

## Tests
Tests need a PostgreSQL database whose name contains `test`. The suite drops and recreates its schema.
```bash
TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/sumt_test npm test
```

## Deploy
See [docs/DEPLOY_RAILWAY.md](docs/DEPLOY_RAILWAY.md).
