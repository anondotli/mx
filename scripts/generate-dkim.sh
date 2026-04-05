#!/bin/bash
set -e

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

KEY_DIR="config/dkim/$DOMAIN"
mkdir -p "$KEY_DIR"

if [ -f "$KEY_DIR/private" ]; then
    echo "Key already exists for $DOMAIN"
else
    echo "Generating DKIM key for $DOMAIN..."
    openssl genrsa -out "$KEY_DIR/private" 2048
    openssl rsa -in "$KEY_DIR/private" -pubout -out "$KEY_DIR/public"
    
    # Extract public key for DNS record
    PUB_KEY=$(grep -v '^-' "$KEY_DIR/public" | tr -d '\n')
    echo "DKIM DNS Record for $DOMAIN:"
    echo "default._domainkey.$DOMAIN. IN TXT \"v=DKIM1; k=rsa; p=$PUB_KEY\""
fi
