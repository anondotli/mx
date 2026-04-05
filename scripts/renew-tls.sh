#!/bin/bash
set -e

# Post-renewal hook for certbot.
# Combines Let's Encrypt certificate files into a single PEM for Haraka,
# then restarts the Haraka container.

CERT_DIR="/etc/letsencrypt/live/mx.anon.li"
HARAKA_TLS_DIR="/opt/anon.li-mx/config/tls"
COMPOSE_FILE="/opt/anon.li-mx/docker-compose.yml"

if [ ! -d "$CERT_DIR" ]; then
    echo "Certificate directory not found: $CERT_DIR"
    exit 1
fi

# Combine private key + fullchain into single PEM (Haraka expects this format)
cat "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem" > "$HARAKA_TLS_DIR/anon.li.pem"
chmod 644 "$HARAKA_TLS_DIR/anon.li.pem"

echo "TLS certificate updated at $HARAKA_TLS_DIR/anon.li.pem"

# Restart Haraka to pick up the new certificate
docker compose -f "$COMPOSE_FILE" restart haraka
echo "Haraka container restarted"
