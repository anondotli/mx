#!/bin/sh
set -eu

DKIM_SOURCE_DIR="${DKIM_SOURCE_DIR:-/etc/haraka/config/dkim-src}"
LOCAL_DKIM_DIR="${LOCAL_DKIM_DIR:-/run/haraka/dkim}"
export LOCAL_DKIM_DIR

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
require_file /etc/haraka/config/tls/anon.li.pem "TLS certificate bundle"

mkdir -p /etc/haraka/queue

# Fix queue directory ownership — Docker volume mounts as root
chown -R haraka:haraka /etc/haraka/queue

warn_missing_dkim_keys
stage_dkim_keys
validate_dkim_runtime_access

# Drop privileges and exec the CMD
exec su-exec haraka "$@"
