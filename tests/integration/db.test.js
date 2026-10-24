'use strict';

// Runs lib/db.js against a real Postgres database migrated with the website's
// prisma/migrations (see README "Testing"). Skipped unless TEST_DATABASE_URL is set.

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const url = process.env.TEST_DATABASE_URL;
const skip = !url && 'TEST_DATABASE_URL not set';

describe('lib/db.js against the website schema', { skip }, () => {
    let db;
    let pg;
    const dkimKey = crypto.randomBytes(32).toString('hex');

    before(() => {
        process.env.DATABASE_URL = url;
        process.env.DKIM_ENCRYPTION_KEY = dkimKey;
        db = require('../../lib/db');
        const { Pool } = require('pg');
        pg = new Pool({ connectionString: url, ssl: false });
    });

    after(async () => {
        await db.close();
        await pg.end();
    });

    const uid = () => crypto.randomBytes(6).toString('hex');

    async function insert(table, row) {
        const cols = Object.keys(row);
        const values = Object.values(row);
        const sql = `INSERT INTO ${table} (${cols.map(c => `"${c}"`).join(', ')})
                     VALUES (${cols.map((_, i) => `$${i + 1}`).join(', ')})`;
        await pg.query(sql, values);
        return row;
    }

    const now = new Date();
    const user = (extra = {}) => insert('users', { id: `u${uid()}`, email: `${uid()}@example.net`, updatedAt: now, ...extra });
    const org = (extra = {}) => insert('organizations', { id: `o${uid()}`, name: 'Team', slug: `team-${uid()}`, updatedAt: now, ...extra });
    const recipient = (extra = {}) => insert('recipients', { id: `r${uid()}`, email: `${uid()}@example.net`, verified: true, updatedAt: now, ...extra });
    const domain = (extra = {}) => insert('domains', { id: `d${uid()}`, domain: `${uid()}.example`, verificationToken: uid(), verified: true, updatedAt: now, ...extra });
    const subscription = (extra = {}) => insert('subscriptions', { id: `s${uid()}`, provider: 'manual', status: 'active', updatedAt: now, ...extra });
    async function alias(extra = {}) {
        const localPart = extra.localPart || uid();
        const domainName = extra.domain || 'anon.li';
        return insert('aliases', { id: `a${uid()}`, email: `${localPart}@${domainName}`, localPart, domain: domainName, updatedAt: now, ...extra });
    }
    const link = (aliasRow, rcpt, ordinal = 0) => insert('alias_recipients', {
        id: `ar${uid()}`, aliasId: aliasRow.id, recipientId: rcpt.id, ordinal, isPrimary: ordinal === 0, updatedAt: now,
    });
    const countAliases = async (email) => (await pg.query('SELECT count(*)::int AS n FROM aliases WHERE email = $1', [email])).rows[0].n;

    describe('lookupAlias', () => {
        it('returns verified recipients in order, skipping unverified ones', async () => {
            const u = await user();
            const a = await alias({ userId: u.id });
            const r1 = await recipient({ userId: u.id, pgpPublicKey: 'KEY' });
            const r2 = await recipient({ userId: u.id, verified: false });
            const r3 = await recipient({ userId: u.id });
            await link(a, r3, 2);
            await link(a, r2, 1);
            await link(a, r1, 0);

            const found = await db.lookupAlias(a.email.toUpperCase());
            assert.equal(found.id, a.id);
            assert.equal(found.userId, u.id);
            assert.deepEqual(found.recipients, [
                { email: r1.email, pgpPublicKey: 'KEY' },
                { email: r3.email, pgpPublicKey: null },
            ]);
        });

        it('falls back to the legacy recipient only when there are no join rows', async () => {
            const u = await user();
            const legacy = await recipient({ userId: u.id });
            const a = await alias({ userId: u.id, recipientId: legacy.id });
            assert.deepEqual((await db.lookupAlias(a.email)).recipients, [{ email: legacy.email, pgpPublicKey: null }]);

            const unverified = await recipient({ userId: u.id, verified: false });
            const b = await alias({ userId: u.id, recipientId: legacy.id });
            await link(b, unverified);
            assert.equal(await db.lookupAlias(b.email), null, 'join rows exist, none verified → no fallback');
        });

        it('rejects inactive, taken-down and orphaned aliases', async () => {
            const u = await user();
            const r = await recipient({ userId: u.id });
            const inactive = await alias({ userId: u.id, active: false });
            const takenDown = await alias({ userId: u.id, taken_down_at: now });
            const orphan = await alias({});
            for (const a of [inactive, takenDown, orphan]) await link(a, r);

            assert.equal(await db.lookupAlias(inactive.email), null);
            assert.equal(await db.lookupAlias(takenDown.email), null);
            assert.equal(await db.lookupAlias(orphan.email), null);
        });

        it('stops delivering custom-domain aliases once another owner holds the verified domain', async () => {
            const previousOwner = await user();
            const newOwner = await user();
            const d = await domain({ userId: previousOwner.id, verified: false });
            const r = await recipient({ userId: previousOwner.id });
            const a = await alias({ userId: previousOwner.id, domain: d.domain });
            await link(a, r);

            // Claim revoked but not superseded: the old owner's aliases keep working
            assert.ok(await db.lookupAlias(a.email));
            assert.equal(await db.canSendAs(a.email), true);

            await domain({ domain: d.domain, userId: newOwner.id });
            assert.equal(await db.lookupAlias(a.email), null);
            assert.equal(await db.canSendAs(a.email), false);
        });

        it('keeps delivering when the verified domain belongs to the same owner (personal and org)', async () => {
            const u = await user();
            const d = await domain({ userId: u.id });
            const r = await recipient({ userId: u.id });
            const a = await alias({ userId: u.id, domain: d.domain });
            await link(a, r);
            assert.ok(await db.lookupAlias(a.email));

            const o = await org();
            const od = await domain({ organizationId: o.id, userId: u.id });
            const orgRecipient = await recipient({ organizationId: o.id });
            const oa = await alias({ organizationId: o.id, userId: null, domain: od.domain });
            await link(oa, orgRecipient);
            assert.ok(await db.lookupAlias(oa.email));
        });
    });

    describe('canSendAs', () => {
        it('allows disabled aliases but not deleted or taken-down ones', async () => {
            const u = await user();
            const disabled = await alias({ userId: u.id, active: false });
            const takenDown = await alias({ userId: u.id, taken_down_at: now, active: false });
            assert.equal(await db.canSendAs(disabled.email), true);
            assert.equal(await db.canSendAs(takenDown.email), false);
            assert.equal(await db.canSendAs(`deleted-${uid()}@anon.li`), false);
        });
    });

    describe('getOwnerAddresses', () => {
        it('lists the owner\'s verified recipient addresses only', async () => {
            const u = await user();
            const mine = await recipient({ userId: u.id, email: `Me+Tag-${uid()}@Example.net` });
            await recipient({ userId: u.id, verified: false });
            const a = await alias({ userId: u.id });
            await recipient({ userId: (await user()).id });
            assert.deepEqual(await db.getOwnerAddresses(a.email.toUpperCase()), [mine.email]);
        });

        it('uses the organization scope for organization aliases', async () => {
            const o = await org();
            const orgRecipient = await recipient({ organizationId: o.id });
            await recipient({ userId: (await user()).id });
            const a = await alias({ organizationId: o.id });
            assert.deepEqual(await db.getOwnerAddresses(a.email), [orgRecipient.email]);
        });
    });

    describe('catch-all', () => {
        async function personalCatchAll(userExtra = {}) {
            const u = await user(userExtra);
            const r = await recipient({ userId: u.id });
            const d = await domain({ userId: u.id, catch_all: true, catch_all_recipient_id: r.id });
            return { u, r, d };
        }

        it('creates a RANDOM alias with its primary recipient, once', async () => {
            const { u, r, d } = await personalCatchAll();
            const email = `hello@${d.domain}`;
            const created = await db.lookupAlias(email);
            assert.equal(created.email, email);
            assert.equal(created.userId, u.id);
            assert.equal(created.organizationId, null);
            assert.deepEqual(created.recipients, [{ email: r.email, pgpPublicKey: null }]);

            const row = (await pg.query('SELECT * FROM aliases WHERE email = $1', [email])).rows[0];
            assert.equal(row.format, 'RANDOM');
            assert.equal(row.recipientId, r.id);
            assert.match(row.id, /^c[a-z0-9]{24}$/);
            const join = (await pg.query('SELECT * FROM alias_recipients WHERE "aliasId" = $1', [row.id])).rows;
            assert.equal(join.length, 1);
            assert.equal(join[0].isPrimary, true);

            assert.equal((await db.lookupAlias(email)).id, created.id);
            assert.equal(await countAliases(email), 1);
        });

        it('creates exactly one alias under concurrent first deliveries', async () => {
            const { d } = await personalCatchAll();
            const email = `race@${d.domain}`;
            const results = await Promise.all(Array.from({ length: 6 }, () => db.lookupAlias(email)));
            assert.equal(new Set(results.map(r => r?.id)).size, 1);
            assert.equal(await countAliases(email), 1);
        });

        it('never resurrects a disabled or taken-down address', async () => {
            const { u, d } = await personalCatchAll();
            const disabled = await alias({ userId: u.id, domain: d.domain, active: false });
            assert.equal(await db.lookupAlias(disabled.email), null);
            assert.equal(await countAliases(disabled.email), 1);
        });

        it('enforces the free quota of 10 random aliases', async () => {
            const { u, d } = await personalCatchAll();
            for (let i = 0; i < 10; i++) await alias({ userId: u.id, format: 'RANDOM' });
            assert.equal(await db.lookupAlias(`over@${d.domain}`), null);
        });

        it('grants Plus via referral and Pro via an org membership (seat inheritance)', async () => {
            const { u, d } = await personalCatchAll({ referral_plus_until: new Date(Date.now() + 86400000) });
            for (let i = 0; i < 10; i++) await alias({ userId: u.id, format: 'RANDOM' });
            assert.equal(await db._internal.getUserAliasTier(u.id), 'plus');
            assert.ok(await db.lookupAlias(`plus@${d.domain}`));

            const member = await user();
            const o = await org();
            await insert('members', { id: `m${uid()}`, organizationId: o.id, userId: member.id });
            await subscription({ organizationId: o.id, product: 'business', tier: 'pro', seats: 5 });
            assert.equal(await db._internal.getUserAliasTier(member.id), 'pro');
        });

        it('ignores lapsed, past-due and non-alias subscriptions', async () => {
            const u = await user();
            await subscription({ userId: u.id, product: 'alias', tier: 'pro', current_period_end: new Date(Date.now() - 3 * 86400000) });
            await subscription({ userId: u.id, product: 'alias', tier: 'pro', status: 'past_due' });
            await subscription({ userId: u.id, product: 'drop', tier: 'pro' });
            assert.equal(await db._internal.getUserAliasTier(u.id), 'free');
            await subscription({ userId: u.id, product: 'bundle', tier: 'plus', current_period_end: new Date(Date.now() - 3600000) });
            assert.equal(await db._internal.getUserAliasTier(u.id), 'plus', 'within the one-day grace');
        });

        it('refuses banned owners and unverified or foreign catch-all recipients', async () => {
            const banned = await personalCatchAll({ banAliasCreation: true });
            assert.equal(await db.lookupAlias(`x@${banned.d.domain}`), null);

            const u = await user();
            const unverified = await recipient({ userId: u.id, verified: false });
            const d1 = await domain({ userId: u.id, catch_all: true, catch_all_recipient_id: unverified.id });
            assert.equal(await db.lookupAlias(`x@${d1.domain}`), null);

            const stranger = await user();
            const foreign = await recipient({ userId: stranger.id });
            const d2 = await domain({ userId: u.id, catch_all: true, catch_all_recipient_id: foreign.id });
            assert.equal(await db.lookupAlias(`x@${d2.domain}`), null);

            const d3 = await domain({ userId: u.id, catch_all: true, catch_all_recipient_id: 'deleted-recipient' });
            assert.equal(await db.lookupAlias(`x@${d3.domain}`), null);
        });

        it('creates organization aliases only for subscribed, unsuspended teams', async () => {
            const creator = await user();
            const o = await org();
            const r = await recipient({ organizationId: o.id, userId: creator.id });
            const d = await domain({ organizationId: o.id, userId: creator.id, catch_all: true, catch_all_recipient_id: r.id });

            assert.equal(await db.lookupAlias(`a@${d.domain}`), null, 'unsubscribed team has no capacity');

            await subscription({ organizationId: o.id, product: 'business', tier: 'pro' });
            const created = await db.lookupAlias(`a@${d.domain}`);
            assert.equal(created.organizationId, o.id);
            assert.equal(created.userId, creator.id);

            await pg.query('UPDATE organizations SET suspended_at = now() WHERE id = $1', [o.id]);
            assert.equal(await db.lookupAlias(`b@${d.domain}`), null);
        });

        it('rejects quoted or over-long local parts and never applies to anon.li', async () => {
            const { d } = await personalCatchAll();
            assert.equal(await db.lookupAlias(`${'x'.repeat(65)}@${d.domain}`), null);
            assert.equal(await db.lookupAlias(`"a b"@${d.domain}`), null);
            assert.equal(await db.lookupAlias(`nobody-${uid()}@anon.li`), null);
        });
    });

    describe('getDkimKey', () => {
        function encryptField(plaintext) {
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(dkimKey, 'hex'), iv);
            const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
            return 'enc:' + Buffer.concat([iv, enc, cipher.getAuthTag()]).toString('base64');
        }

        it('decrypts the key of a verified domain with a published DKIM record', async () => {
            const d = await domain({ dkimPrivateKey: encryptField('PEM'), dkimVerified: true, dkimSelector: 'default' });
            assert.deepEqual(await db.getDkimKey(d.domain.toUpperCase()), { domain: d.domain, selector: 'default', privateKey: 'PEM' });
        });

        it('ignores keys whose DNS record is not verified, and unverified domains', async () => {
            const d1 = await domain({ dkimPrivateKey: encryptField('PEM'), dkimVerified: false });
            const d2 = await domain({ dkimPrivateKey: encryptField('PEM'), dkimVerified: true, verified: false });
            assert.equal(await db.getDkimKey(d1.domain), null);
            assert.equal(await db.getDkimKey(d2.domain), null);
        });
    });

    describe('incrementAliasStats', () => {
        it('counts forwarded and blocked mail', async () => {
            const a = await alias({ userId: (await user()).id });
            await db.incrementAliasStats(a.id, { forwarded: 1 });
            await db.incrementAliasStats(a.id, { blocked: 1 });
            const row = (await pg.query('SELECT "emailsReceived", "emailsBlocked", "lastEmailAt" FROM aliases WHERE id = $1', [a.id])).rows[0];
            assert.equal(row.emailsReceived, 1);
            assert.equal(row.emailsBlocked, 1);
            assert.ok(row.lastEmailAt);
        });
    });
});
