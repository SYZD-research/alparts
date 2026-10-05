FROM node:24-alpine3.22@sha256:191c9f0080fcbbc6547a85dc0ff7988072214a355aabdc1d2ec55a7dae5eea8a AS build

WORKDIR /app
RUN apk add --no-cache 'libcrypto3=3.5.9-r0' 'libssl3=3.5.9-r0'
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY patches ./patches
COPY packages/shared/package.json packages/shared/package.json
COPY packages/server/package.json packages/server/package.json
COPY packages/client/package.json packages/client/package.json
RUN pnpm install --frozen-lockfile

COPY packages ./packages
RUN pnpm build

FROM node:24-alpine3.22@sha256:191c9f0080fcbbc6547a85dc0ff7988072214a355aabdc1d2ec55a7dae5eea8a AS runtime

ENV NODE_ENV=production \
    BIND_HOST=127.0.0.1
WORKDIR /app
RUN apk add --no-cache 'libcrypto3=3.5.9-r0' 'libssl3=3.5.9-r0'
RUN corepack enable
RUN mkdir -p /var/lib/alparts-audit && chown node:node /var/lib/alparts-audit

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
COPY packages/shared/package.json packages/shared/package.json
COPY packages/server/package.json packages/server/package.json
RUN pnpm install --prod --frozen-lockfile --ignore-scripts --filter @alparts/server... \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /opt/yarn-v1.22.22 /root/.cache /root/.local/share/pnpm

COPY --from=build /app/packages/shared/dist packages/shared/dist
COPY --from=build /app/packages/server/dist packages/server/dist
COPY --from=build /app/packages/server/src/db/migrations packages/server/migrations
COPY --from=build /app/packages/client/dist packages/client/dist
COPY --from=build /app/packages/client/dist/THIRD_PARTY_NOTICES.txt /app/THIRD_PARTY_NOTICES.txt

USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "--permission", "--allow-fs-read=/app", "--allow-fs-read=/run/secrets", "--allow-fs-read=/var/lib/alparts-audit", "--allow-fs-read=/run/alparts-witness", "--allow-fs-write=/var/lib/alparts-audit", "--allow-worker", "--disallow-code-generation-from-strings", "packages/server/dist/index.js"]
