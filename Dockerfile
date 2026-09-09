# Zero-dependency app: no `npm install`, no build step, no native modules.
FROM node:24-alpine

ENV NODE_ENV=production \
    PORT=7060 \
    HOST=0.0.0.0 \
    DB_PATH=/data/app.db

WORKDIR /app
COPY package.json ./
COPY src ./src

# /data is a volume; make it writable by the unprivileged `node` user.
RUN mkdir -p /data && chown -R node:node /data /app
USER node

VOLUME ["/data"]
EXPOSE 7060

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+ (process.env.PORT||7060) +'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.js"]
