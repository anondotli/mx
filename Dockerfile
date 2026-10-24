FROM node:24-alpine

# Runtime packages
RUN apk add --no-cache netcat-openbsd openssl su-exec libstdc++

# Create app directory
WORKDIR /etc/haraka

# Haraka generates config/dhparams.pem at startup when it is missing, but the
# service user cannot write config/, so every boot spawned a failing openssl
# run. Generate it once here, in its own layer so code and dependency changes
# keep the cache.
RUN mkdir -p config && openssl dhparam -out config/dhparams.pem 2048

# Install dependencies from the lockfile. iconv is a native module, so the
# build toolchain is added and removed in the same layer. Optional packages are
# Haraka's bundled plugins (unused: ours are in plugins/) and @msimerson/stun,
# whose failed public-IP lookup throws an uncaught exception that stops Haraka
# (a DNS hiccup at the first outbound delivery); route_mx recognises our own
# MX without it.
COPY package.json package-lock.json ./
RUN apk add --no-cache --virtual .build-deps python3 make g++ \
    && npm ci --omit=dev --omit=optional \
    && npm cache clean --force \
    && apk del .build-deps

# Copy application code (root-owned and read-only for the service user)
COPY . .

# The service user only needs to write the outbound queue. Strip group/world
# write bits copied from the build context (e.g. a checkout on a filesystem
# that reports 0777).
RUN addgroup -S haraka && adduser -S haraka -G haraka \
    && chmod -R go-w /etc/haraka \
    && mkdir -p /etc/haraka/queue \
    && chown haraka:haraka /etc/haraka/queue

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports
EXPOSE 25

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD printf "EHLO healthcheck\r\nQUIT\r\n" | nc -w5 localhost 25 | grep -q "250" || exit 1

# Start Haraka
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["npx", "haraka", "-c", "/etc/haraka"]
