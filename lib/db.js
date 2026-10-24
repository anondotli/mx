'use strict';

const { Pool } = require('pg');
const crypto = require('crypto');
const { OWN_DOMAIN } = require('./constants');
const { splitAddress } = require('./address');

// Direct access to the website's Postgres database (schema owned by the
// website's prisma/schema.prisma — column names below are the real, @map'd
// ones from its migrations).

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

let pool = null;

// Mirrors the website's lib/database-ssl.ts: remote databases use TLS (managed
// Postgres, certificate not verified), a loopback database connects in
// plaintext. An explicit sslmode in DATABASE_URL overrides this either way.
function sslOption(connectionString) {
    try {
        const hostname = new URL(connectionString).hostname.toLowerCase();
        return LOOPBACK_HOSTS.has(hostname) ? false : { rejectUnauthorized: false };
    } catch (_err) {
        return { rejectUnauthorized: false };
    }
}

function getPool() {
    if (pool) return pool;

    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) {
        throw new Error('DATABASE_URL environment variable is required');
    }

    pool = new Pool({
        connectionString,
        ssl: sslOption(connectionString),
        max: 10,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 10_000,
    });

    pool.on('error', (err) => {
        // Idle client errors must not crash the process
        console.error('[db] idle client error:', err.message);
    });

    return pool;
}

async function query(text, params) {
    return getPool().query(text, params);
}

// Random alias quotas mirror the website's config/plans.ts (alias.*.random).
// Business plans always resolve to the pro tier.
const ALIAS_RANDOM_LIMIT = { free: 10, plus: 100, pro: -1 };
// An entitling subscription row (website lib/subscription-entitlement.ts): an
// entitling status, and the period not lapsed past the one-day access grace.
const ENTITLING = `
    s.status IN ('active', 'trialing')
    AND (s.current_period_end IS NULL OR s.current_period_end > now() - interval '1 day')`;
// A plan granting an alias tier (bundle and business count for every product).
const ALIAS_PLAN = `s.tier IN ('plus', 'pro') AND s.product IN ('alias', 'bundle', 'business')`;

// Personal alias tier, mirroring lib/entitlements.ts: the user's personal
// subscriptions, plans inherited from every organization they are a member
// of, and an active referral Plus window.
async function getUserAliasTier(userId) {
    const res = await query(
        `SELECT COALESCE(bool_or(s.tier = 'pro'), false) AS pro,
                COALESCE(bool_or(s.tier = 'plus'), false) AS plus,
                COALESCE((SELECT u.referral_plus_until > now() FROM users u WHERE u.id = $1), false) AS referral
         FROM subscriptions s
         WHERE ${ENTITLING}
           AND ${ALIAS_PLAN}
           AND ((s."userId" = $1 AND s."organizationId" IS NULL)
                OR s."organizationId" IN (SELECT m."organizationId" FROM members m WHERE m."userId" = $1))`,
        [userId],
    );
    const row = res.rows[0] || {};
    if (row.pro) return 'pro';
    if (row.plus || row.referral) return 'plus';
    return 'free';
}

// Organization alias tier, or null when the organization has no entitling
// subscription of any product — a zero-capacity workspace (the website's
// assertOrgPlanActive checks status and period only, not the product).
async function getOrgAliasTier(organizationId) {
    const res = await query(
        `SELECT count(*) > 0 AS subscribed,
                COALESCE(bool_or(s.tier = 'pro' AND ${ALIAS_PLAN}), false) AS pro,
                COALESCE(bool_or(s.tier = 'plus' AND ${ALIAS_PLAN}), false) AS plus
         FROM subscriptions s
         WHERE s."organizationId" = $1 AND ${ENTITLING}`,
        [organizationId],
    );
    const row = res.rows[0] || {};
    if (!row.subscribed) return null;
    if (row.pro) return 'pro';
    if (row.plus) return 'plus';
    return 'free';
}

function toRecipient(row) {
    return { email: row.email, pgpPublicKey: row.pgpPublicKey || null };
}

// An alias row may be used while it is not taken down, still has an owner and,
// for a custom domain, no *different* owner holds the verified claim on that
// domain: the website leaves the previous owner's aliases active when a claim
// was revoked before being superseded, and mail for that domain now belongs to
// the new owner. ($2 = the system domain)
const ALIAS_USABLE = `
    a.taken_down_at IS NULL
    AND (a."organizationId" IS NOT NULL OR a."userId" IS NOT NULL)
    AND (a.domain = $2 OR NOT EXISTS (
        SELECT 1 FROM domains d
        WHERE d.domain = a.domain
          AND d.verified = true
          AND NOT (d."organizationId" IS NOT DISTINCT FROM a."organizationId"
                   AND (a."organizationId" IS NOT NULL
                        OR d."userId" IS NOT DISTINCT FROM a."userId"))
    ))`;

// The alias row for an address, whether it may receive mail (usable and
// active), and its recipients — the join table rows and the legacy single
// recipientId — in one round trip.
async function getAliasRow(email) {
    const res = await query(
        `SELECT a.id, a.email, a."localPart", a.domain, a."userId", a."organizationId",
                (a.active = true AND ${ALIAS_USABLE}) AS deliverable,
                COALESCE((
                    SELECT json_agg(json_build_object(
                               'email', r.email, 'pgpPublicKey', r."pgpPublicKey", 'verified', r.verified)
                           ORDER BY ar.ordinal ASC, ar."createdAt" ASC)
                    FROM alias_recipients ar
                    JOIN recipients r ON r.id = ar."recipientId"
                    WHERE ar."aliasId" = a.id
                ), '[]'::json) AS joined_recipients,
                (SELECT json_build_object('email', lr.email, 'pgpPublicKey', lr."pgpPublicKey")
                 FROM recipients lr
                 WHERE lr.id = a."recipientId" AND lr.verified = true) AS legacy_recipient
         FROM aliases a
         WHERE a.email = $1
         LIMIT 1`,
        [email, OWN_DOMAIN],
    );
    return res.rows[0] || null;
}

// Verified forwarding recipients: the join table rows, falling back to the
// legacy single recipientId only when the alias has no join rows at all
// (lib/services/alias.ts).
function aliasRecipients(row) {
    const joined = row.joined_recipients || [];
    const rows = joined.length > 0 ? joined.filter(r => r.verified) : [row.legacy_recipient].filter(Boolean);
    return rows.map(toRecipient);
}

// The forwarding target of a deliverable alias row, or null when it has no
// verified recipient left.
function toForwardingAlias(row) {
    if (!row?.deliverable) return null;
    const recipients = aliasRecipients(row);
    if (recipients.length === 0) return null;
    return {
        id: row.id,
        email: row.email,
        localPart: row.localPart,
        domain: row.domain,
        userId: row.userId,
        organizationId: row.organizationId,
        recipients,
    };
}

function normalizeEmail(emailRaw) {
    const email = String(emailRaw || '').trim().toLowerCase();
    const parts = splitAddress(email);
    return parts ? { email, localPart: parts.local, domain: parts.domain } : null;
}

async function lookupAlias(emailRaw) {
    const addr = normalizeEmail(emailRaw);
    if (!addr) return null;

    // Disabled, taken-down or superseded aliases are rejected — never
    // re-created through catch-all.
    const alias = await getAliasRow(addr.email);
    if (alias) return toForwardingAlias(alias);

    return createCatchAllAlias(addr);
}

// Whether replies may still be sent as this alias (exists, not taken down, and
// its custom domain is not now owned by someone else). A user-disabled alias
// can still reply to existing conversations.
async function canSendAs(emailRaw) {
    const addr = normalizeEmail(emailRaw);
    if (!addr) return false;
    const res = await query(
        `SELECT 1 FROM aliases a WHERE a.email = $1 AND ${ALIAS_USABLE} LIMIT 1`,
        [addr.email, OWN_DOMAIN],
    );
    return res.rows.length > 0;
}

// Verified recipient addresses of the alias's owner (personal, or the alias's
// organization): the mailboxes allowed to reply as the alias.
async function getOwnerAddresses(aliasEmail) {
    const res = await query(
        `SELECT r.email
         FROM aliases a
         JOIN recipients r
           ON r.verified = true
          AND r."organizationId" IS NOT DISTINCT FROM a."organizationId"
          AND (a."organizationId" IS NOT NULL OR r."userId" = a."userId")
         WHERE a.email = $1`,
        [String(aliasEmail || '').toLowerCase()],
    );
    return res.rows.map(r => r.email);
}

// Same shape as Prisma's cuid ids ("c" + 24 lowercase alphanumerics).
const ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
function newId() {
    let id = 'c';
    for (const byte of crypto.randomBytes(24)) id += ID_ALPHABET[byte % ID_ALPHABET.length];
    return id;
}

// RFC 5321 dot-atom local part (no quoted strings), at most 64 octets.
const CATCH_ALL_LOCAL_PART = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const SERIALIZATION_FAILURE = '40001';

// Catch-all: auto-create an alias for any address on a verified catch-all
// domain, within the owner's random-alias quota (mirrors the website's
// AliasService.createAlias rules for personal and organization owners).
async function createCatchAllAlias({ email, localPart, domain }) {
    if (domain === OWN_DOMAIN) return null;
    if (localPart.length > 64 || !CATCH_ALL_LOCAL_PART.test(localPart)) return null;

    const domainRes = await query(
        `SELECT "userId", "organizationId", catch_all_recipient_id
         FROM domains
         WHERE domain = $1 AND verified = true AND catch_all = true
         LIMIT 1`,
        [domain],
    );
    if (domainRes.rows.length === 0) return null;
    const owner = domainRes.rows[0];
    if (!owner.catch_all_recipient_id) return null;

    const [tier, recipient] = await Promise.all([
        getCatchAllTier(owner),
        getCatchAllRecipient(owner),
    ]);
    if (!tier || !recipient) return null;

    const limit = ALIAS_RANDOM_LIMIT[tier];
    for (let attempt = 0; ; attempt++) {
        const client = await getPool().connect();
        let outcome;
        try {
            outcome = await insertCatchAllAlias(client, { email, localPart, domain, owner, recipient, limit });
        } catch (err) {
            await client.query('ROLLBACK').catch(() => {});
            if (err.code === SERIALIZATION_FAILURE && attempt < 2) continue;
            throw err;
        } finally {
            client.release();
        }

        if (outcome.quotaReached) return null;

        if (outcome.aliasId) {
            return {
                id: outcome.aliasId,
                email,
                localPart,
                domain,
                userId: owner.userId,
                organizationId: owner.organizationId,
                recipients: [toRecipient(recipient)],
            };
        }

        // Created concurrently by another delivery — use that row.
        return toForwardingAlias(await getAliasRow(email));
    }
}

// The owner's alias tier for catch-all creation, or null when the owner may
// not create aliases (suspended or unsubscribed team, banned user).
async function getCatchAllTier(owner) {
    if (owner.organizationId) {
        const org = await query(`SELECT suspended_at FROM organizations WHERE id = $1`, [owner.organizationId]);
        if (org.rows.length === 0 || org.rows[0].suspended_at) return null;
        return getOrgAliasTier(owner.organizationId);
    }
    if (!owner.userId) return null;
    const user = await query(`SELECT banned, "banAliasCreation" FROM users WHERE id = $1`, [owner.userId]);
    if (user.rows.length === 0 || user.rows[0].banned || user.rows[0].banAliasCreation) return null;
    return getUserAliasTier(owner.userId);
}

// The catch-all recipient has no foreign key: it must still exist, be verified
// and belong to the domain owner's scope.
async function getCatchAllRecipient(owner) {
    const res = await query(
        `SELECT id, email, "pgpPublicKey" FROM recipients
         WHERE id = $1
           AND verified = true
           AND "organizationId" IS NOT DISTINCT FROM $2::text
           AND ($2::text IS NOT NULL OR "userId" = $3::text)`,
        [owner.catch_all_recipient_id, owner.organizationId, owner.userId],
    );
    return res.rows[0] || null;
}

// One SERIALIZABLE attempt: re-count the quota and insert the alias with its
// primary recipient row. Resolves { quotaReached }, { aliasId } or {} when the
// address was created concurrently.
async function insertCatchAllAlias(client, { email, localPart, domain, owner, recipient, limit }) {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');

    if (limit !== -1) {
        const count = owner.organizationId
            ? await client.query(
                `SELECT COUNT(*)::int AS n FROM aliases
                 WHERE "organizationId" = $1 AND format = 'RANDOM'`,
                [owner.organizationId],
            )
            : await client.query(
                `SELECT COUNT(*)::int AS n FROM aliases
                 WHERE "userId" = $1 AND "organizationId" IS NULL AND format = 'RANDOM'`,
                [owner.userId],
            );
        if (count.rows[0].n >= limit) {
            await client.query('ROLLBACK');
            return { quotaReached: true };
        }
    }

    const created = await client.query(
        `INSERT INTO aliases
            (id, email, "localPart", domain, "userId", "organizationId", "recipientId",
             format, active, "createdAt", "updatedAt")
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'RANDOM', true, NOW(), NOW())
         ON CONFLICT (email) DO NOTHING
         RETURNING id`,
        [newId(), email, localPart, domain, owner.userId, owner.organizationId, recipient.id],
    );
    if (created.rows.length === 0) {
        await client.query('ROLLBACK');
        return {};
    }

    await client.query(
        `INSERT INTO alias_recipients
            (id, "aliasId", "recipientId", ordinal, "isPrimary", "createdAt", "updatedAt")
         VALUES ($1, $2, $3, 0, true, NOW(), NOW())`,
        [newId(), created.rows[0].id, recipient.id],
    );

    await client.query('COMMIT');
    return { aliasId: created.rows[0].id };
}

async function incrementAliasStats(aliasId, { forwarded = 0, blocked = 0 } = {}) {
    if (!aliasId) return;
    if (forwarded <= 0 && blocked <= 0) return;

    await query(
        `UPDATE aliases
         SET "emailsReceived" = "emailsReceived" + $1,
             "emailsBlocked" = "emailsBlocked" + $2,
             "lastEmailAt" = CASE WHEN $1 > 0 THEN NOW() ELSE "lastEmailAt" END,
             "updatedAt" = NOW()
         WHERE id = $3`,
        [forwarded, blocked, aliasId],
    );
}

// Custom-domain DKIM keys are stored encrypted by the website
// (lib/field-encryption.ts): "enc:" + base64(12-byte IV ‖ ciphertext ‖ 16-byte
// GCM tag), AES-256-GCM keyed by the hex DKIM_ENCRYPTION_KEY. Values without
// the prefix are legacy plaintext.
function decryptDkimKey(value) {
    if (!value.startsWith('enc:')) return value;

    const keyHex = process.env.DKIM_ENCRYPTION_KEY || '';
    if (!/^[0-9a-f]{64}$/i.test(keyHex)) {
        throw new Error('DKIM_ENCRYPTION_KEY is missing or not 64 hex characters');
    }
    const data = Buffer.from(value.slice(4), 'base64');
    if (data.length < 12 + 16) throw new Error('Encrypted DKIM key is truncated');

    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), data.subarray(0, 12));
    decipher.setAuthTag(data.subarray(data.length - 16));
    return Buffer.concat([
        decipher.update(data.subarray(12, data.length - 16)),
        decipher.final(),
    ]).toString('utf8');
}

// The signing key for a verified custom domain whose DKIM record is published
// (a freshly regenerated key has dkimVerified = false until DNS catches up).
async function getDkimKey(domainRaw) {
    const domain = String(domainRaw || '').trim().toLowerCase();
    const res = await query(
        `SELECT "dkimPrivateKey", "dkimSelector", domain
         FROM domains
         WHERE domain = $1 AND verified = true AND "dkimVerified" = true
         LIMIT 1`,
        [domain],
    );

    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    if (!row.dkimPrivateKey) return null;

    return {
        domain: row.domain,
        selector: row.dkimSelector || 'default',
        privateKey: decryptDkimKey(row.dkimPrivateKey),
    };
}

async function close() {
    if (pool) {
        await pool.end();
        pool = null;
    }
}

module.exports = {
    lookupAlias,
    canSendAs,
    getOwnerAddresses,
    incrementAliasStats,
    getDkimKey,
    close,
    // Exposed for tests / introspection only
    _internal: {
        getUserAliasTier,
        getOrgAliasTier,
        decryptDkimKey,
        sslOption,
        newId,
        ALIAS_RANDOM_LIMIT,
        setQueryClient(fake) { pool = fake; },
    },
};
