'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { Address } = require('@haraka/email-address');
const { OK, DENY, DENYSOFT } = require('../helpers/haraka');
const db = require('../../lib/db');
const replyToken = require('../../lib/reply-token');
const plugin = require('../../plugins/rcpt_to.reply');

const instance = { loginfo() {}, logerror() {} };

describe('rcpt_to.reply RCPT', () => {
    beforeEach(() => replyToken._clearLocalStore());

    async function rcpt(address, notes = {}) {
        const txn = { notes, mail_from: new Address('<me@example.net>') };
        let result;
        await plugin.check_reply_token.call(instance, (code, msg) => { result = { code, msg }; }, { transaction: txn }, [{ address: address }]);
        return { ...result, notes: txn.notes };
    }

    it('accepts a valid token for an alias that may still send', async (t) => {
        t.mock.method(db, 'canSendAs', async (email) => email === 'shop@anon.li');
        const token = await replyToken.create('news@shop.example', 'shop@anon.li', 'me@example.net');
        const r = await rcpt(`${token}@reply.anon.li`);
        assert.equal(r.code, OK);
        assert.deepEqual(r.notes.reply, {
            originalSender: 'news@shop.example',
            aliasEmail: 'shop@anon.li',
            recipientEmail: 'me@example.net',
        });
        assert.equal(r.notes.is_reply, true);
    });

    it('rejects tokens of deleted, taken-down or superseded aliases', async (t) => {
        t.mock.method(db, 'canSendAs', async () => false);
        const token = await replyToken.create('news@shop.example', 'gone@anon.li', 'me@example.net');
        const r = await rcpt(`${token}@reply.anon.li`);
        assert.equal(r.code, DENY);
        assert.equal(r.notes.reply, undefined);
    });

    it('rejects permanently when the original sender cannot receive replies', async (t) => {
        t.mock.method(db, 'canSendAs', async () => true);
        const token = await replyToken.create('not an address', 'shop@anon.li', 'me@example.net');
        assert.equal((await rcpt(`${token}@reply.anon.li`)).code, DENY);
    });

    it('tempfails when the alias check cannot reach the database', async (t) => {
        t.mock.method(db, 'canSendAs', async () => { throw new Error('timeout'); });
        const token = await replyToken.create('news@shop.example', 'shop@anon.li', 'me@example.net');
        assert.equal((await rcpt(`${token}@reply.anon.li`)).code, DENYSOFT);
    });

    it('rejects unknown tokens', async () => {
        assert.equal((await rcpt('neverIssued@reply.anon.li')).code, DENY);
    });

    it('answers 452 to a second recipient in the same transaction', async () => {
        const r = await rcpt('anything@reply.anon.li', { alias: {}, accepted_rcpt: 'shop@anon.li' });
        assert.equal(r.code, DENYSOFT);
        assert.equal(r.msg.code, 452);
    });

    it('accepts a repeated RCPT of the same token once', async () => {
        const r = await rcpt('Tok@reply.anon.li', { reply: {}, accepted_rcpt: 'tok@reply.anon.li' });
        assert.equal(r.code, OK);
    });

    it('ignores other domains', async () => {
        assert.equal((await rcpt('shop@anon.li')).code, undefined);
    });
});

describe('rcpt_to.reply sender check (after DATA)', () => {
    const reply = { originalSender: 'news@shop.example', aliasEmail: 'shop@anon.li', recipientEmail: 'John.Doe+anon@gmail.com' };
    const pass = { status: { result: 'pass' } };

    async function check({ sender, from = '', mailauth }) {
        const txn = {
            notes: { reply, mailauth },
            mail_from: new Address(sender ? `<${sender}>` : '<>'),
            header: { get: (name) => (name === 'From' ? from : '') },
        };
        let result;
        await plugin.check_reply_sender.call(instance, (code, msg) => { result = { code, msg }; }, { transaction: txn });
        return result;
    }

    it('accepts the forwarded-to mailbox when SPF passes (case, +tag and Gmail dots ignored)', async (t) => {
        t.mock.method(db, 'getOwnerAddresses', async () => assert.fail('fast path needs no lookup'));
        const r = await check({ sender: 'johndoe@gmail.com', mailauth: { spf: pass } });
        assert.equal(r.code, undefined);
    });

    it('accepts another verified recipient of the owner', async (t) => {
        t.mock.method(db, 'getOwnerAddresses', async (alias) => (alias === 'shop@anon.li' ? ['Work@Example.org'] : []));
        const r = await check({ sender: 'work@example.org', mailauth: { spf: pass } });
        assert.equal(r.code, undefined);
    });

    it('accepts a From address with a DKIM signature aligned to its domain (no DMARC record)', async (t) => {
        t.mock.method(db, 'getOwnerAddresses', async () => []);
        const r = await check({
            sender: 'bounce-123@mailer.example',
            from: 'Me <johndoe@gmail.com>',
            mailauth: { spf: { status: { result: 'fail' } }, dmarc: { status: { result: 'none' } }, dkim: { results: [{ status: { result: 'pass' }, signingDomain: 'gmail.com' }] } },
        });
        assert.equal(r.code, undefined);
    });

    it('refuses a replayed DKIM signature under a forged envelope sender', async (t) => {
        t.mock.method(db, 'getOwnerAddresses', async () => []);
        // An attacker's own gmail.com-signed message, resent with MAIL FROM:<owner>
        const r = await check({
            sender: 'johndoe@gmail.com',
            from: 'Attacker <attacker@gmail.com>',
            mailauth: { spf: { status: { result: 'fail' } }, dmarc: { status: { result: 'pass' } }, dkim: { results: [{ status: { result: 'pass' }, signingDomain: 'gmail.com' }] } },
        });
        // Only the attacker's own From authenticates, and it is not the owner
        assert.equal(r.code, DENY);
        assert.match(r.msg, /recipient addresses/);
    });

    it('does not treat a +tagged sender as the untagged registered address', async (t) => {
        t.mock.method(db, 'getOwnerAddresses', async () => ['bob@provider.example']);
        const r = await check({ sender: 'bob+x@provider.example', mailauth: { spf: pass } });
        assert.equal(r.code, DENY);
    });

    it('accepts an owner address authenticated through DMARC on From (e.g. "send mail as")', async (t) => {
        t.mock.method(db, 'getOwnerAddresses', async () => ['me@custom.example']);
        const r = await check({
            sender: 'account@provider.example',
            from: 'Me <me@custom.example>',
            mailauth: { spf: { status: { result: 'pass' } }, dmarc: pass },
        });
        assert.equal(r.code, undefined);
    });

    it('refuses a forged envelope sender that does not authenticate', async (t) => {
        t.mock.method(db, 'getOwnerAddresses', async () => assert.fail('no lookup for unauthenticated senders'));
        const r = await check({ sender: 'johndoe@gmail.com', from: 'johndoe@gmail.com', mailauth: { spf: { status: { result: 'fail' } }, dmarc: { status: { result: 'fail' } } } });
        assert.equal(r.code, DENY);
        assert.match(r.msg, /SPF\/DKIM/);
    });

    it('refuses authenticated senders that are not the owner', async (t) => {
        t.mock.method(db, 'getOwnerAddresses', async () => ['work@example.org']);
        const r = await check({ sender: 'stranger@elsewhere.example', mailauth: { spf: pass } });
        assert.equal(r.code, DENY);
        assert.match(r.msg, /recipient addresses/);
    });

    it('tempfails when authentication or the owner lookup could not run', async (t) => {
        assert.equal((await check({ sender: 'johndoe@gmail.com', mailauth: { spf: { status: { result: 'temperror' } } } })).code, DENYSOFT);
        assert.equal((await check({ sender: 'johndoe@gmail.com', mailauth: undefined })).code, DENYSOFT);
        t.mock.method(db, 'getOwnerAddresses', async () => { throw new Error('db down'); });
        assert.equal((await check({ sender: 'other@example.org', mailauth: { spf: pass } })).code, DENYSOFT);
    });

    it('ignores transactions that are not replies', async () => {
        let code = 'unset';
        await plugin.check_reply_sender.call(instance, (c) => { code = c; }, { transaction: { notes: {} } });
        assert.equal(code, undefined);
    });
});
