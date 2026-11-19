import { loadEnv } from './config/env.js';
import { buildApp } from './app.js';
import { bootstrapAdmin } from './services/admin-auth.service.js';

async function main() {
  const env = loadEnv();
  const app = await buildApp(env);
  await bootstrapAdmin(app.ctx, app.log);

  const shutdown = async (signal: string) => {
    app.log.info(`${signal} received, shutting down`);
    await app.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ port: env.PORT, host: env.HOST });
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
