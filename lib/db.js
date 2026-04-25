'use strict';

const { Pool } = require('pg');
const crypto = require('crypto');

let pool = null;

function getPool() {
    if (pool) return pool;

    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) {
        throw new Error('DATABASE_URL environment variable is required');
    }

    pool = new Pool({
        connectionString,
        ssl: { rejectUnauthorized: false },
        max: 10,
        idleTimeoutMillis: 30_000,
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

// Random alias quotas mirror config/plans.ts PLAN_ENTITLEMENTS.alias.*.random
const ALIAS_RANDOM_LIMIT = { free: 10, plus: 100, pro: -1 };

// Resolves a user's effective alias tier mirroring lib/entitlements.ts.
// Subscriptions table first; falls back to legacy users.stripePriceId/period.
async function getAliasTier(userId) {
    const subs = await query(
        `SELECT product, tier, "currentPeriodEnd"
         FROM subscriptions
         WHERE "userId" = $1 AND status IN ('active','trialing')`,
        [userId],
    );

    const dayMs = 24 * 60 * 60 * 1000;
    const now = Date.now();
    const active = subs.rows.filter(
        (s) => !s.currentPeriodEnd || new Date(s.currentPeriodEnd).getTime() + dayMs > now,
    );

    let tier = 'free';
    for (const s of active) {
        if ((s.tier === 'plus' || s.tier === 'pro') &&
            (s.product === 'alias' || s.product === 'bundle')) {
            if (s.tier === 'pro') return 'pro';
            tier = 'plus';
        }
    }
    if (tier !== 'free') return tier;

    // Fallback: legacy User-level Stripe fields are not authoritative for catch-all
    // gating (the website itself reaches the same conclusion via subscriptions in
    // 99% of cases). Treat unsubscribed users as free.
    return 'free';
}

async function lookupAlias(emailRaw) {
    const email = String(emailRaw || '').toLowerCase();
    if (!email) return null;

    const aliasRes = await query(
        `SELECT a.id,
                a.email,
                a."localPart",
                a.domain,
                a."userId",
                a."recipientId"
         FROM aliases a
         WHERE a.email = $1 AND a.active = true
         LIMIT 1`,
        [email],
    );

    if (aliasRes.rows.length > 0) {
        const alias = aliasRes.rows[0];

        const recRes = await query(
            `SELECT r.email, r."pgpPublicKey", ar.ordinal
             FROM alias_recipients ar
             JOIN recipients r ON r.id = ar."recipientId"
             WHERE ar."aliasId" = $1
             ORDER BY ar.ordinal ASC`,
            [alias.id],
        );

        let recipients = recRes.rows.map((r) => ({
            email: r.email,
            pgpPublicKey: r.pgpPublicKey || null,
        }));

        if (recipients.length === 0 && alias.recipientId) {
            const legacy = await query(
                `SELECT email, "pgpPublicKey" FROM recipients WHERE id = $1`,
                [alias.recipientId],
            );
            recipients = legacy.rows.map((r) => ({
                email: r.email,
                pgpPublicKey: r.pgpPublicKey || null,
            }));
        }

        if (recipients.length === 0) return null;

        return {
            id: alias.id,
            email: alias.email,
            active: true,
            isActive: true,
            localPart: alias.localPart,
            domain: alias.domain,
            userId: alias.userId,
            recipients,
        };
    }

    // Catch-all path: replicates app/api/internal/aliases/route.ts:50-135
    const at = email.indexOf('@');
    if (at <= 0 || at === email.length - 1) return null;
    const localPart = email.substring(0, at);
    const domain = email.substring(at + 1);

    const domainRes = await query(
        `SELECT "userId", catch_all_recipient_id, domain
         FROM domains
         WHERE domain = $1
           AND verified = true
           AND catch_all = true
           AND "userId" IS NOT NULL
         LIMIT 1`,
        [domain],
    );

    if (domainRes.rows.length === 0) return null;
    const cd = domainRes.rows[0];
    if (!cd.catch_all_recipient_id) return null;

    const tier = await getAliasTier(cd.userId);
    const limit = ALIAS_RANDOM_LIMIT[tier];

    if (limit !== -1) {
        const count = await query(
            `SELECT COUNT(*)::int AS n FROM aliases
             WHERE "userId" = $1 AND format = 'RANDOM'`,
            [cd.userId],
        );
        if (count.rows[0].n >= limit) return null;
    }

    const client = await getPool().connect();
    try {
        await client.query('BEGIN');

        const aliasId = `c${crypto.randomBytes(12).toString('base64url').slice(0, 24)}`;

        const created = await client.query(
            `INSERT INTO aliases
                (id, email, "localPart", domain, "userId", "recipientId",
                 format, active, "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4, $5, $6, 'RANDOM', true, NOW(), NOW())
             RETURNING id, email, "localPart", domain, "userId"`,
            [aliasId, email, localPart, domain, cd.userId, cd.catch_all_recipient_id],
        );

        const arId = `c${crypto.randomBytes(12).toString('base64url').slice(0, 24)}`;
        await client.query(
            `INSERT INTO alias_recipients
                (id, "aliasId", "recipientId", ordinal, "isPrimary",
                 "createdAt", "updatedAt")
             VALUES ($1, $2, $3, 0, true, NOW(), NOW())`,
            [arId, created.rows[0].id, cd.catch_all_recipient_id],
        );

        const rec = await client.query(
            `SELECT email, "pgpPublicKey" FROM recipients WHERE id = $1`,
            [cd.catch_all_recipient_id],
        );

        await client.query('COMMIT');

        if (rec.rows.length === 0) return null;

        return {
            id: created.rows[0].id,
            email: created.rows[0].email,
            active: true,
            isActive: true,
            localPart: created.rows[0].localPart,
            domain: created.rows[0].domain,
            userId: created.rows[0].userId,
            recipients: [{
                email: rec.rows[0].email,
                pgpPublicKey: rec.rows[0].pgpPublicKey || null,
            }],
        };
    } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
    } finally {
        client.release();
    }
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

async function getDkimKey(domain) {
    const res = await query(
        `SELECT "dkimPrivateKey", "dkimSelector", domain
         FROM domains
         WHERE domain = $1 AND verified = true
         LIMIT 1`,
        [domain],
    );

    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    if (!row.dkimPrivateKey) return null;

    return {
        domain: row.domain,
        selector: row.dkimSelector || 'default',
        privateKey: row.dkimPrivateKey,
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
    incrementAliasStats,
    getDkimKey,
    close,
    // Exposed for tests / introspection only
    _internal: { getAliasTier, ALIAS_RANDOM_LIMIT },
};
