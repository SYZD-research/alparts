import type { Config } from 'drizzle-kit';

export default {
  schema: './src/db/schema.ts',
  out: './src/db/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    url: 'postgresql://alparts:alparts_dev@localhost:5433/alparts',
  },
} satisfies Config;
