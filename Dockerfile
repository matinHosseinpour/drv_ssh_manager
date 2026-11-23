FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY public ./public
COPY tests ./tests
RUN npm run check && npm run test:cli && npm prune --omit=dev

FROM node:22-bookworm-slim
ENV NODE_ENV=production LISTEN_HOST=0.0.0.0 PORT=3080 DATABASE_PATH=/app/data/connector.sqlite
RUN groupadd --gid 10001 connector && useradd --uid 10001 --gid connector --no-create-home connector
WORKDIR /app
COPY --from=build --chown=connector:connector /app/package.json /app/package-lock.json ./
COPY --from=build --chown=connector:connector /app/node_modules ./node_modules
COPY --from=build --chown=connector:connector /app/dist ./dist
COPY --from=build --chown=connector:connector /app/public ./public
RUN mkdir /app/data && chown connector:connector /app/data
USER connector
EXPOSE 3080
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 CMD ["node", "dist/healthcheck.js"]
CMD ["node", "dist/main.js"]
