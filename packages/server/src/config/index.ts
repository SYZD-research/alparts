const env = process.env;

export const config = {
  port: parseInt(env.PORT || '3000', 10),
  nodeEnv: env.NODE_ENV || 'development',

  db: {
    host: env.DB_HOST || 'localhost',
    port: parseInt(env.DB_PORT || '5433', 10),
    user: env.DB_USER || 'alparts',
    password: env.DB_PASSWORD || 'alparts_dev',
    database: env.DB_NAME || 'alparts',
    get url() {
      return env.DATABASE_URL || `postgresql://${this.user}:${this.password}@${this.host}:${this.port}/${this.database}`;
    },
  },

  jwt: {
    secret: env.JWT_SECRET || 'dev-secret-change-in-production',
    expiresIn: env.JWT_EXPIRES_IN || '7d',
  },

  minio: {
    endPoint: env.MINIO_ENDPOINT || 'localhost',
    port: parseInt(env.MINIO_PORT || '9000', 10),
    accessKey: env.MINIO_ACCESS_KEY || 'minioadmin',
    secretKey: env.MINIO_SECRET_KEY || 'minioadmin',
    bucket: env.MINIO_BUCKET || 'alparts',
    useSSL: env.MINIO_USE_SSL === 'true',
  },

  cors: {
    origin: env.CORS_ORIGIN || 'http://localhost:5173',
  },
} as const;
