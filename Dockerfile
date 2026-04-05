FROM node:24-alpine

# Install runtime packages plus native build dependencies for iconv
RUN apk add --no-cache netcat-openbsd openssl su-exec libstdc++ \
    && apk add --no-cache --virtual .build-deps python3 make g++

# Update npm to latest version to fix notice
RUN npm install -g npm@latest

# Create app directory
WORKDIR /etc/haraka

# Copy package dependencies
COPY package.json package-lock.json ./

# Install dependencies
RUN npm install --omit=dev \
    && apk del .build-deps

# Copy application code
COPY . .

# Set permissions
RUN addgroup -S haraka && adduser -S haraka -G haraka \
    && mkdir -p /etc/haraka/queue \
    && chown -R haraka:haraka /etc/haraka

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports
EXPOSE 25 587

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD printf "EHLO healthcheck\r\nQUIT\r\n" | nc -w5 localhost 25 | grep -q "250" || exit 1

# Start Haraka
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["npx", "haraka", "-c", "/etc/haraka"]
