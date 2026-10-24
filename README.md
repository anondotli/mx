# anon.li Email Server

A secure, privacy-focused Haraka email server for anonymous email forwarding.

## Features

- **Anonymous Forwarding**: Accepts emails for `@anon.li` aliases and verified custom domains (including catch-all), forwarding them to the alias owner's verified recipients
- **Reply System**: Replies via `@reply.anon.li` tokenized addresses; only an allowlist of headers is passed on, so the user's address, IP and mail client never reach the correspondent
- **PGP Encryption**: Forwards PGP/MIME-encrypted copies to recipients who uploaded a public key
- **Privacy Protection**: Removes tracking pixels and tracking link parameters from forwarded copies; bounces that would reveal the recipient's real address are never passed back to the sender
- **SRS Support**: Implements the Sender Rewriting Scheme to keep SPF passing when forwarding
- **DKIM / ARC Signing**: Signs all outbound mail (custom domains with their own key) and ARC-seals forwarded mail
- **Rate Limiting**: Redis-backed rate limiting per connecting IP and per alias
- **Custom Domains**: Supports user-verified custom domains with per-domain DKIM keys

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  External       │     │    Haraka       │     │   PostgreSQL    │
│  Sender         │────▶│    MTA          │────▶│ (website's DB:  │
└─────────────────┘     └─────────────────┘     │  aliases, ...)  │
                               │                └─────────────────┘
                               ▼
                        ┌─────────────────┐
                        │  Upstash Redis  │
                        │ (rate limits,   │
                        │  reply/bounce   │
                        │  tokens)        │
                        └─────────────────┘
```

## Installation

### Prerequisites

- Docker and Docker Compose
- Node.js 24+ (for local development)
- Access to the website's PostgreSQL database
- Upstash Redis (recommended; in-memory fallback is not persistent)

### Quick Start

1. **Clone and configure**:
   ```bash
   cp .env.example .env
   # Set MAIL_API_SECRET, DATABASE_URL, DKIM_ENCRYPTION_KEY and the Upstash credentials
   ```

2. **Generate DKIM keys**:
   ```bash
   ./scripts/generate-dkim.sh anon.li
   ./scripts/generate-dkim.sh reply.anon.li
   ```
   The generated keys stay on the host under `config/dkim/` (private keys
   `0600`) and are mounted into the container at runtime. On startup, the
   entrypoint stages them into a private runtime directory owned by the
   `haraka` user. They are intentionally not baked into the Docker image.

3. **Add DNS records** (output from script):
   ```
   default._domainkey.anon.li. IN TXT "v=DKIM1; k=rsa; p=..."
   default._domainkey.reply.anon.li. IN TXT "v=DKIM1; k=rsa; p=..."
   ```

4. **Place TLS certificates**:
   ```bash
   (umask 077 && cat privkey.pem fullchain.pem > config/tls/anon.li.pem)
   ```
   `scripts/renew-tls.sh` does this as a certbot post-renewal hook. Like the
   DKIM keys, the bundle is staged into a `haraka`-owned copy at startup, so
   the host file stays owner-only.

5. **Start the server**:
   ```bash
   docker compose up -d --build
   ```
   The container validates `MAIL_API_SECRET`, `DATABASE_URL`,
   `DKIM_ENCRYPTION_KEY` and the TLS bundle at startup, and warns when local
   DKIM keys are missing so deliverability issues are visible immediately.

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `MAIL_API_SECRET` | Signs SRS return paths; keep it stable | Yes |
| `DATABASE_URL` | Postgres connection string for the same database the website uses | Yes |
| `DKIM_ENCRYPTION_KEY` | The website's key (64 hex chars) for decrypting custom-domain DKIM keys | Yes |
| `UPSTASH_REDIS_REST_URL` | Upstash Redis REST endpoint | Recommended |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash Redis auth token | Recommended |
| `DKIM_REQUIRED_DOMAINS` | Space-separated local DKIM domains to stage/warn about at startup | No |
| `LOCAL_DKIM_DIR` | Internal runtime directory for staged DKIM keys | No |

Without Redis, reply tokens, bounce tokens, the reply Message-ID map and rate
limits live in memory and are lost on restart (replies to mail forwarded before
a restart are rejected).

### Plugins

| Plugin | Purpose |
|--------|---------|
| `tls` | STARTTLS (TLS 1.2+) |
| `limit-upstash` | Per-IP connection rate limiting (IPv6 per /64; Redis + in-memory fallback) and a cap on rejected recipients per connection |
| `mailauth` | Inbound SPF / DKIM / ARC / DMARC validation (haraka-plugin-mailauth, vendored for Haraka 3.3) |
| `rcpt_to.bounce` | Validates SRS and `BNC=` return paths |
| `rcpt_to.anonli` | Validates aliases and catch-all (direct Postgres) + per-alias rate limiting; creates catch-all aliases at queue time, rate-limited per domain |
| `rcpt_to.reply` | Resolves reply-token addresses (Redis) and checks the alias may still send |
| `data.loop_detect` | Rejects mail loops |
| `data.spam_check` | DMARC/SPF policy enforcement |
| `arc.sign` | ARC sealing for forwarded mail |
| `dkim.custom` | DKIM signing (local keys; custom-domain keys from Postgres) |
| `queue.forward` | Forwarding (SRS, tracking removal, PGP, reply rewriting, bounce privacy, stats) |

### Mail flows

- **Forward** (`alias@anon.li` / custom domain): one copy per verified
  recipient, each with its own `Reply-To` reply token, SRS envelope, tracking
  removed and optionally PGP-encrypted. Read-receipt and followup headers
  (`Disposition-Notification-To`, `Mail-Followup-To`, ...) are removed so the
  recipient's client never answers the sender directly. Mail that passes a
  strict DMARC policy gets `From` rewritten to `"Name via anon.li" <alias>`;
  mail failing `p=reject` is refused, and mail failing `p=quarantine` keeps its
  `From` so the recipient's provider applies the policy.
  A new address on a catch-all domain is accepted at `RCPT` if the owner has
  quota left, but its alias is only created once the message has passed every
  check, so probes and rejected mail never use up the quota.
- **Reply** (`<token>@reply.anon.li`): accepted only from one of the alias
  owner's verified recipient addresses, authenticated by SPF/DKIM (envelope)
  or DMARC (`From`), and sent to the original correspondent as the alias. Only content and threading headers (`Subject`, `In-Reply-To`,
  `References`, `Content-*`, ...) are kept; `Received`, `Sender`, `Reply-To`,
  read-receipt requests, client IPs and the original `Date` are dropped. The
  `Message-ID` is replaced by one derived from it, and the IDs of earlier
  replies are rewritten in later threading headers (and mapped back on mail to
  the same alias, so threading keeps working).
- **Bounces**: a failed forward is never reported back to the original sender
  (the bounce would name the recipient's real address). Bounced replies are
  delivered to the alias owner.
- **Reserved addresses** (`config/reserved_aliases.json`, e.g. `hi@anon.li`)
  are relayed to the team mailbox at Purelymail.
- **Mail for a domain whose MX is this server** (a reply to another anon.li
  alias, a bounced reply) is handed back to the local listener instead of being
  skipped by outbound's loop protection.

A message is accepted for one alias (or reply token / return path) per SMTP
transaction; additional recipients get `452 4.5.3` and are retried by the
sending server in a separate transaction.

## DNS Configuration

### For anon.li

```dns
; MX Record
anon.li.                IN MX   10 mx.anon.li.

; SPF (mx.anon.li must be authorized)
anon.li.                IN TXT  "v=spf1 mx ~all"

; DKIM (generated by script)
default._domainkey.anon.li. IN TXT "v=DKIM1; k=rsa; p=..."

; DMARC
_dmarc.anon.li.         IN TXT  "v=DMARC1; p=quarantine"
```

### For Custom Domains

Users must add (verified by the website):
1. MX record pointing to `mx.anon.li`
2. SPF record including `include:anon.li`
3. DKIM record (provided in dashboard)
4. Verification TXT record

## Security Features

- **STARTTLS** with TLS 1.2+
- **Constant-time** SRS hash comparison
- **Input validation** on all email addresses
- **Rate limiting** per connecting IP (IPv6 per /64), per alias and per catch-all domain (new aliases); connections are dropped after 10 rejected recipients
- **Message size limit** of 25 MiB
- **DKIM/SPF/DMARC/ARC** for email authentication
- **PGP encryption** for enhanced privacy
- **Tracking removal** for privacy protection

## Monitoring

```bash
docker compose logs -f haraka
```

Production notes:
- DKIM private keys and TLS certificates are mounted at runtime; keep them out of the image build context.
- DKIM keys and the TLS bundle are staged into `haraka`-owned copies on startup so the unprivileged `haraka` process can read them without loosening host file permissions.
- ARC signing reuses the same key lookup path as DKIM signing: staged local key first, database fallback second.
- Docker Compose requests an IPv6-enabled user-defined bridge network for Haraka.
- Outbound delivery uses Haraka's default dual-stack behavior, which prefers IPv6 when the container has working IPv6 egress.
- Docker daemon IPv6 settings in `/etc/docker/daemon.json` are optional for this setup. They are only needed if you want to customize Docker's IPv6 address pools or enable IPv6 on the default `bridge` network.
- Message data with bare line feeds (LF without CR) is refused with `451 Bare line-feed` — Haraka's SMTP smuggling defence.
- The image installs no optional npm packages: Haraka's bundled plugins are unused, and without `@msimerson/stun` Haraka does not query Google's STUN servers for its public IP (`route_mx` recognises our own MX from `config/me`; the IP is declared as `public_ip` in `config/smtp.ini`).
- Logs never contain the real address of an alias's recipient (`queue.forward` names it `recipient 1/2`), except Haraka's own outbound lines for a failed delivery. Compose keeps them with Docker's `local` driver, rotated at 5 × 20 MB.

Health check:
```bash
nc -z localhost 25 && echo "OK"
```

## Development

```bash
# Install dependencies
npm install

# Run locally
npm start

# Lint and run unit tests
npm run lint
npm test
```

### Database integration tests

`tests/integration/db.test.js` runs `lib/db.js` against a real database built
from the website's migrations. It is skipped unless `TEST_DATABASE_URL` is set:

```bash
podman run -d --rm --name anonli-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=anonli \
  -p 127.0.0.1:55432:5432 docker.io/library/postgres:16-alpine
for m in $(ls -d ../anon.li/prisma/migrations/*/ | sort); do
  podman exec -i anonli-test-pg psql -q -v ON_ERROR_STOP=1 -U postgres -d anonli < "$m/migration.sql"
done
TEST_DATABASE_URL=postgresql://postgres:test@127.0.0.1:55432/anonli npm test
```

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

Because anon.li-mx is network-facing server software, the AGPL requires that
anyone running a modified version on a publicly accessible server make the
corresponding source code available to its users.
