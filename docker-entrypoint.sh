#!/bin/sh
set -eu

DKIM_SOURCE_DIR="${DKIM_SOURCE_DIR:-/etc/haraka/config/dkim-src}"
LOCAL_DKIM_DIR="${LOCAL_DKIM_DIR:-/run/haraka/dkim}"
export LOCAL_DKIM_DIR

TLS_SOURCE_DIR="${TLS_SOURCE_DIR:-/etc/haraka/config/tls-src}"
TLS_DIR=/etc/haraka/config/tls
TLS_BUNDLE=anon.li.pem

require_env() {
    var_name="$1"
    eval "value=\${$var_name:-}"
    if [ -z "$value" ]; then
        echo "Missing required environment variable: $var_name" >&2
        exit 1
    fi
}

require_file() {
    path="$1"
    description="$2"
    if [ ! -r "$path" ]; then
        echo "Missing required $description at $path" >&2
        exit 1
    fi
}

warn_missing_dkim_keys() {
    domains="${DKIM_REQUIRED_DOMAINS:-anon.li reply.anon.li}"

    for domain in $domains; do
        path="$DKIM_SOURCE_DIR/$domain/private"
        if [ ! -r "$path" ]; then
            echo "Warning: no local DKIM key for $domain at $path; ARC/DKIM will rely on API fallback" >&2
        fi
    done
}

stage_dkim_keys() {
    domains="${DKIM_REQUIRED_DOMAINS:-anon.li reply.anon.li}"

    mkdir -p "$LOCAL_DKIM_DIR"
    chown haraka:haraka "$LOCAL_DKIM_DIR"
    chmod 700 "$LOCAL_DKIM_DIR"

    for domain in $domains; do
        src_dir="$DKIM_SOURCE_DIR/$domain"
        dest_dir="$LOCAL_DKIM_DIR/$domain"

        if [ ! -d "$src_dir" ]; then
            continue
        fi

        mkdir -p "$dest_dir"

        if [ -r "$src_dir/private" ]; then
            cp "$src_dir/private" "$dest_dir/private"
            chown haraka:haraka "$dest_dir/private"
            chmod 600 "$dest_dir/private"
        fi

        if [ -r "$src_dir/public" ]; then
            cp "$src_dir/public" "$dest_dir/public"
            chown haraka:haraka "$dest_dir/public"
            chmod 644 "$dest_dir/public"
        fi

        chown haraka:haraka "$dest_dir"
        chmod 700 "$dest_dir"
    done
}

# Like the DKIM keys, the TLS bundle (private key + chain) is mounted from the
# host and staged into a haraka-owned 0600 copy, so the host file can stay
# 0600 too. A bundle mounted directly at $TLS_DIR (older layout) is used as is.
stage_tls_bundle() {
    if [ -r "$TLS_SOURCE_DIR/$TLS_BUNDLE" ]; then
        mkdir -p "$TLS_DIR"
        cp "$TLS_SOURCE_DIR/$TLS_BUNDLE" "$TLS_DIR/$TLS_BUNDLE"
        chown haraka:haraka "$TLS_DIR" "$TLS_DIR/$TLS_BUNDLE"
        chmod 700 "$TLS_DIR"
        chmod 600 "$TLS_DIR/$TLS_BUNDLE"
    fi

    require_file "$TLS_DIR/$TLS_BUNDLE" "TLS certificate bundle"
    if ! su-exec haraka test -r "$TLS_DIR/$TLS_BUNDLE"; then
        echo "TLS certificate bundle at $TLS_DIR/$TLS_BUNDLE is not readable by haraka" >&2
        exit 1
    fi
}

# The website stores custom-domain DKIM keys encrypted with this key; without
# it every custom-domain reply would be signed as anon.li and fail DMARC.
require_dkim_encryption_key() {
    require_env DKIM_ENCRYPTION_KEY
    if ! printf '%s' "$DKIM_ENCRYPTION_KEY" | grep -Eq '^[0-9a-fA-F]{64}$'; then
        echo "DKIM_ENCRYPTION_KEY must be 64 hexadecimal characters (the website's value)" >&2
        exit 1
    fi
}

validate_dkim_runtime_access() {
    domains="${DKIM_REQUIRED_DOMAINS:-anon.li reply.anon.li}"

    for domain in $domains; do
        src_path="$DKIM_SOURCE_DIR/$domain/private"
        dest_path="$LOCAL_DKIM_DIR/$domain/private"

        if [ -r "$src_path" ] && ! su-exec haraka test -r "$dest_path"; then
            echo "Warning: staged DKIM key for $domain is not readable by haraka at $dest_path" >&2
        fi
    done
}

require_env MAIL_API_SECRET
require_env DATABASE_URL
require_dkim_encryption_key
stage_tls_bundle

mkdir -p /etc/haraka/queue

# Fix queue directory ownership — Docker volume mounts as root
chown -R haraka:haraka /etc/haraka/queue

warn_missing_dkim_keys
stage_dkim_keys
validate_dkim_runtime_access

# Drop privileges and exec the CMD
exec su-exec haraka "$@"
