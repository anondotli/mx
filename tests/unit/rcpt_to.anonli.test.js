'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { OK, DENY, DENYSOFT } = require('../helpers/haraka');
const db = require('../../lib/db');
const plugin = require('../../plugins/rcpt_to.anonli');

const ALIAS = { id: 'a1', email: 'shop@anon.li', recipients: [{ email: 'me@example.net', pgpPublicKey: null }] };

describe('rcpt_to.anonli', () => {
    const instance = Object.create(plugin);
    Object.assign(instance, {
        config: { get: () => ({ main: { alias_rate_limit_window: '300', alias_rate_limit_count: '2', catch_all_rate_limit_count: '2' } }) },
        register_hook() {},
        loginfo() {},
        logerror() {},
    });

    before(() => plugin.register.call(instance));
    after(() => plugin.shutdown.call(instance));

    async function rcpt(address, notes = {}) {
        const txn = { notes };
        let result;
        await plugin.check_alias.call(instance, (code, msg) => { result = { code, msg }; }, { transaction: txn }, [{ address: address }]);
        return { ...result, notes: txn.notes };
    }

    it('accepts a known alias and stores it for the queue plugin', async (t) => {
        t.mock.method(db, 'lookupAlias', async (email) => (email === 'shop@anon.li' ? ALIAS : null));
        const r = await rcpt('Shop@Anon.li');
        assert.equal(r.code, OK);
        assert.equal(r.notes.alias, ALIAS);
        assert.equal(r.notes.accepted_rcpt, 'shop@anon.li');
    });

    it('rejects unknown addresses permanently', async (t) => {
        t.mock.method(db, 'lookupAlias', async () => null);
        assert.equal((await rcpt('nobody@anon.li')).code, DENY);
    });

    it('tempfails when the database is unavailable', async (t) => {
        t.mock.method(db, 'lookupAlias', async () => { throw new Error('connection refused'); });
        assert.equal((await rcpt('shop@anon.li')).code, DENYSOFT);
    });

    it('answers 452 to a second alias so the sender retries it separately', async (t) => {
        t.mock.method(db, 'lookupAlias', async () => assert.fail('must not look up'));
        const r = await rcpt('other@anon.li', { alias: ALIAS, accepted_rcpt: 'shop@anon.li' });
        assert.equal(r.code, DENYSOFT);
        assert.equal(r.msg.code, 452);
    });

    it('accepts the same alias twice in one transaction', async () => {
        assert.equal((await rcpt('shop@anon.li', { alias: ALIAS, accepted_rcpt: 'shop@anon.li' })).code, OK);
    });

    it('routes reserved addresses to the Purelymail relay, one per transaction', async () => {
        const r = await rcpt('support@anon.li');
        assert.equal(r.code, OK);
        assert.equal(r.notes.purelymail_relay, true);
        const relayed = { purelymail_relay: true, purelymail_recipient: 'support@anon.li', accepted_rcpt: 'support@anon.li' };
        assert.equal((await rcpt('abuse@anon.li', { ...relayed })).msg.code, 452);
        assert.equal((await rcpt('shop@anon.li', { ...relayed })).msg.code, 452);
        assert.equal((await rcpt('support@anon.li', { ...relayed })).code, OK, 'a repeat is accepted');
        assert.equal((await rcpt('support@anon.li', { alias: ALIAS, accepted_rcpt: 'shop@anon.li' })).msg.code, 452);
    });

    it('answers 452 when mixed with a reply or bounce recipient', async () => {
        assert.equal((await rcpt('shop@anon.li', { reply: {}, accepted_rcpt: 'tok@reply.anon.li' })).msg.code, 452);
        assert.equal((await rcpt('shop@anon.li', { bounce: {}, accepted_rcpt: 'bnc=x@anon.li' })).msg.code, 452);
    });

    it('leaves reply-token addresses to rcpt_to.reply', async () => {
        assert.equal((await rcpt('tok@reply.anon.li')).code, undefined);
    });

    it('rate-limits each alias (in-memory fallback)', async (t) => {
        t.mock.method(db, 'lookupAlias', async () => ({ ...ALIAS, email: 'busy@anon.li' }));
        assert.equal((await rcpt('busy@anon.li')).code, OK);
        assert.equal((await rcpt('busy@anon.li')).code, OK);
        assert.equal((await rcpt('busy@anon.li')).code, DENYSOFT);
    });

    describe('catch-all creation (queue hook)', () => {
        const pendingFor = (email) => ({
            id: null, email, domain: email.split('@')[1], recipients: ALIAS.recipients, catchAll: { limit: 10 },
        });

        async function queue(notes) {
            const txn = { notes };
            let result;
            await plugin.create_catch_all_alias.call(instance, (code, msg) => { result = { code, msg }; }, { transaction: txn });
            return { ...result, notes: txn.notes };
        }

        it('accepts a catch-all address at RCPT without creating its alias', async (t) => {
            const pending = pendingFor('new@catch.example');
            t.mock.method(db, 'lookupAlias', async () => pending);
            const create = t.mock.method(db, 'createCatchAllAlias', async () => assert.fail('must not create at RCPT'));
            const r = await rcpt('new@catch.example');
            assert.equal(r.code, OK);
            assert.equal(r.notes.alias, pending);
            assert.equal(create.mock.callCount(), 0);
        });

        it('creates the alias once the message passed every check, then continues to queue.forward', async (t) => {
            const pending = pendingFor('new@made.example');
            const created = { ...ALIAS, id: 'c1', email: 'new@made.example' };
            const create = t.mock.method(db, 'createCatchAllAlias', async () => created);
            const r = await queue({ alias: pending });
            assert.equal(r.code, undefined);
            assert.equal(r.notes.alias, created);
            assert.equal(create.mock.calls[0].arguments[0], pending);
        });

        it('leaves existing aliases and other mail alone', async (t) => {
            t.mock.method(db, 'createCatchAllAlias', async () => assert.fail('must not create'));
            assert.equal((await queue({ alias: ALIAS })).notes.alias, ALIAS);
            assert.equal((await queue({ reply: {} })).code, undefined);
        });

        it('rejects the message when the quota filled up after RCPT', async (t) => {
            t.mock.method(db, 'createCatchAllAlias', async () => null);
            assert.equal((await queue({ alias: pendingFor('late@full.example') })).code, DENY);
        });

        it('tempfails when the database is unavailable', async (t) => {
            t.mock.method(db, 'createCatchAllAlias', async () => { throw new Error('connection refused'); });
            assert.equal((await queue({ alias: pendingFor('x@down.example') })).code, DENYSOFT);
        });

        it('rate-limits new aliases per domain (in-memory fallback)', async (t) => {
            const create = t.mock.method(db, 'createCatchAllAlias', async (p) => ({ ...ALIAS, email: p.email }));
            assert.equal((await queue({ alias: pendingFor('a@flood.example') })).code, undefined);
            assert.equal((await queue({ alias: pendingFor('b@flood.example') })).code, undefined);
            assert.equal((await queue({ alias: pendingFor('c@flood.example') })).code, DENYSOFT);
            assert.equal(create.mock.callCount(), 2);
            assert.equal((await queue({ alias: pendingFor('a@other.example') })).code, undefined, 'per domain');
        });
    });
});
