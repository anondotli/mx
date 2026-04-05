#!/bin/sh
# Fix queue directory ownership — Docker volume mounts as root
chown -R haraka:haraka /etc/haraka/queue

# Drop privileges and exec the CMD
exec su-exec haraka "$@"
