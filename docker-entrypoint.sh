#!/bin/sh
set -eu

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
        path="/etc/haraka/config/dkim/$domain/private"
        if [ ! -r "$path" ]; then
            echo "Warning: no local DKIM key for $domain at $path; ARC/DKIM will rely on API fallback" >&2
        fi
    done
}

require_env MAIL_API_SECRET
require_file /etc/haraka/config/tls/anon.li.pem "TLS certificate bundle"

mkdir -p /etc/haraka/queue

# Fix queue directory ownership — Docker volume mounts as root
chown -R haraka:haraka /etc/haraka/queue

warn_missing_dkim_keys

# Drop privileges and exec the CMD
exec su-exec haraka "$@"
