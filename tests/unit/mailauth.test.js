'use strict';

// plugins/mailauth.js (vendored haraka-plugin-mailauth) against Haraka's own
// envelope addresses and message stream, with DNS answered by a stub resolver.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Address } = require('@haraka/email-address');
const { dkimSign } = require('mailauth/lib/dkim/sign');

const { receivedTransaction } = require('../helpers/haraka');
const mailauth = require('../../plugins/mailauth');

function setup(records) {
    const errors = [];
    const plugin = Object.assign(Object.create(mailauth), {
        config: { get: () => ({ dns: { maxLookups: 50 }, minBitLength: 1024 }) },
        register_hook() {},
        logerror: (err) => errors.push(err),
    });
    plugin.register();
    plugin.resolver = async (name, type) => {
        const record = records[`${type} ${name}`];
        if (record) return record;
        throw Object.assign(new Error(`no ${type} record for ${name}`), { code: 'ENOTFOUND' });
    };
    return { plugin, errors };
}

function connectionFor(txn) {
    txn.results = { add() {} };
    return {
        transaction: txn,
        remote: { ip: '192.0.2.1' },
        hello: { host: 'mail.shop.example' },
        local: { host: 'mx.anon.li' },
        notes: {},
        auth_results() {},
    };
}

// Runs a hook to completion, failing if it calls next more than once.
function callHook(plugin, hook, ...args) {
    return new Promise((resolve, reject) => {
        let calls = 0;
        plugin[hook]((...result) => {
            if (++calls > 1) reject(new Error(`${hook} called next twice`));
            else setImmediate(() => resolve(result));
        }, ...args);
    });
}

const SPF_PASS = { 'TXT shop.example': [['v=spf1 ip4:192.0.2.1 -all']] };

describe('mailauth MAIL hook', () => {
    it('reads the envelope sender from Haraka\'s Address (a getter, not a method)', async () => {
        const { plugin, errors } = setup(SPF_PASS);
        const txn = await receivedTransaction('Subject: hi\r\n\r\nbody\r\n', { mailFrom: new Address('<news@shop.example>') });

        await callHook(plugin, 'hook_mail', connectionFor(txn), [txn.mail_from, []]);
        assert.equal(txn.notes.mailauth.sender, 'news@shop.example');
        assert.equal(txn.notes.mailauth.spf.status.result, 'pass');
        assert.deepEqual(errors, []);
    });

    it('checks the HELO identity for a null sender', async () => {
        const { plugin, errors } = setup({ 'TXT mail.shop.example': [['v=spf1 ip4:192.0.2.1 -all']] });
        const txn = await receivedTransaction('Subject: hi\r\n\r\nbody\r\n', { mailFrom: new Address('<>') });

        await callHook(plugin, 'hook_mail', connectionFor(txn), [txn.mail_from, []]);
        assert.equal(txn.notes.mailauth.sender, '');
        assert.equal(txn.notes.mailauth.spf.status.result, 'pass');
        assert.deepEqual(errors, []);
    });
});

describe('mailauth DATA verification', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const dnsKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const signedBy = {
        'TXT s1._domainkey.shop.example': [[`v=DKIM1; k=rsa; p=${dnsKey}`]],
        'TXT _dmarc.shop.example': [['v=DMARC1; p=reject']],
    };

    // Body lines starting with "." are stored dot-stuffed; DKIM must see them
    // as sent.
    const message = [
        'From: Shop <news@shop.example>',
        'To: shop@anon.li',
        'Subject: Weekly',
        'MIME-Version: 1.0',
        'Content-Type: text/plain',
        '',
        '.dotted line',
        '..two dots',
        '.',
        'done',
        '',
    ].join('\r\n');

    async function signed(body = message) {
        const { signatures } = await dkimSign(message, {
            canonicalization: 'relaxed/relaxed',
            algorithm: 'rsa-sha256',
            signatureData: [{ signingDomain: 'shop.example', selector: 's1', privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' }) }],
        });
        return signatures + body;
    }

    async function verify(raw, records) {
        const { plugin, errors } = setup(records);
        const txn = await receivedTransaction(raw, { mailFrom: new Address('<news@shop.example>') });
        const connection = connectionFor(txn);
        await callHook(plugin, 'hook_mail', connection, [txn.mail_from, []]);
        await callHook(plugin, 'hook_data_post', connection);
        assert.deepEqual(errors, []);
        return txn.notes.mailauth;
    }

    it('verifies DKIM over the de-stuffed body and evaluates DMARC', async () => {
        const auth = await verify(await signed(), signedBy);
        assert.equal(auth.dkim.results[0].status.result, 'pass', auth.dkim.results[0].status.comment);
        assert.equal(auth.dmarc.status.result, 'pass');
        assert.equal(auth.dmarc.policy, 'reject');
    });

    it('reports a DMARC failure with the policy data.spam_check enforces', async () => {
        const tampered = (await signed()).replace('done', 'changed');
        const auth = await verify(tampered, signedBy);
        assert.equal(auth.dkim.results[0].status.result, 'neutral', 'mailauth reports a body hash mismatch as neutral');
        assert.equal(auth.dmarc.status.result, 'fail');
        assert.equal(auth.dmarc.policy, 'reject');
    });
});
