'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const path = require('node:path');
const { dkimVerify } = require('mailauth/lib/dkim/verify');
const { receivedTransaction, readStored } = require('../helpers/haraka');
const dkimCustom = require('../../plugins/dkim.custom');
const dkimKeys = require('../../lib/dkim-keys');

describe('getLocalKeyPath()', () => {
    it('uses LOCAL_DKIM_DIR when configured', () => {
        const previous = process.env.LOCAL_DKIM_DIR;
        process.env.LOCAL_DKIM_DIR = '/run/haraka/dkim';

        try {
            assert.equal(
                dkimKeys.getLocalKeyPath('anon.li'),
                path.resolve('/run/haraka/dkim', 'anon.li', 'private')
            );
        } finally {
            if (previous === undefined) {
                delete process.env.LOCAL_DKIM_DIR;
            } else {
                process.env.LOCAL_DKIM_DIR = previous;
            }
        }
    });

    it('falls back to the repository config directory by default', () => {
        const previous = process.env.LOCAL_DKIM_DIR;
        delete process.env.LOCAL_DKIM_DIR;

        try {
            assert.match(
                dkimKeys.getLocalKeyPath('anon.li'),
                /config[\\/]dkim[\\/]anon\.li[\\/]private$/
            );
        } finally {
            if (previous !== undefined) {
                process.env.LOCAL_DKIM_DIR = previous;
            }
        }
    });
});

describe('DKIM signing verified by mailauth', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keys = {
        'anon.li': privateKey.export({ type: 'pkcs1', format: 'pem' }),
        'custom.example': privateKey.export({ type: 'pkcs8', format: 'pem' }),
    };
    const dnsKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const resolver = async (name, type) => {
        if (type === 'TXT' && /^default\._domainkey\.(anon\.li|custom\.example)$/.test(name)) {
            return [[`v=DKIM1; k=rsa; p=${dnsKey}`]];
        }
        const err = new Error(`no record for ${name}`);
        err.code = 'ENOTFOUND';
        throw err;
    };

    async function signAndVerify(raw, notes = {}) {
        const txn = await receivedTransaction(raw, { notes });
        const plugin = Object.create(dkimCustom);
        plugin.get_key = async (domain) => (keys[domain] ? { privateKey: keys[domain], selector: 'default' } : null);
        plugin.logerror = (msg) => assert.fail(msg);
        plugin.logwarn = () => {};
        await new Promise(resolve => dkimCustom.sign_message.call(plugin, resolve, { transaction: txn }));
        const result = await dkimVerify(await readStored(txn), { resolver });
        return result.results[0];
    }

    const message = (headers, body = 'Hello\r\n.leading dot line\r\n\r\n') =>
        `${headers.join('\r\n')}\r\n\r\n${body}`;

    it('passes for a simple message', async () => {
        const r = await signAndVerify(message(['From: a@anon.li', 'To: b@example.com', 'Subject: hi']));
        assert.equal(r.status.result, 'pass', r.status.comment);
        assert.equal(r.signingDomain, 'anon.li');
    });

    it('passes when signed headers are folded (Content-Type boundary, long Subject)', async () => {
        const r = await signAndVerify(message([
            'From: "Someone" <a@anon.li>',
            'To: b@example.com,',
            ' c@example.com',
            'Subject: a very long subject that the sending client',
            '\tfolded onto a second line',
            'MIME-Version: 1.0',
            'Content-Type: multipart/alternative;',
            '\tboundary="xyz"',
        ], '--xyz\r\nContent-Type: text/plain\r\n\r\nhi\r\n--xyz--\r\n'));
        assert.equal(r.status.result, 'pass', r.status.comment);
    });

    it('signs the bottom-most instance of a repeated header', async () => {
        const r = await signAndVerify(message(['From: a@anon.li', 'To: b@example.com', 'To: c@example.com', 'Subject: hi']));
        assert.equal(r.status.result, 'pass', r.status.comment);
    });

    it('passes for an empty body and for trailing whitespace in the body', async () => {
        assert.equal((await signAndVerify(message(['From: a@anon.li', 'Subject: x'], ''))).status.result, 'pass');
        assert.equal((await signAndVerify(message(['From: a@anon.li', 'Subject: x'], 'line  \t\r\n\r\n'))).status.result, 'pass');
    });

    it('signs with the domain chosen in notes.dkim_domain', async () => {
        const r = await signAndVerify(message(['From: me@custom.example', 'Subject: hi']), { dkim_domain: 'custom.example' });
        assert.equal(r.status.result, 'pass', r.status.comment);
        assert.equal(r.signingDomain, 'custom.example');
    });

    it('falls back to anon.li when the chosen domain has no key', async () => {
        const r = await signAndVerify(message(['From: me@nokey.example', 'Subject: hi']), { dkim_domain: 'nokey.example' });
        assert.equal(r.status.result, 'pass', r.status.comment);
        assert.equal(r.signingDomain, 'anon.li');
    });

    it('never signs as the domain in a (possibly spoofed) From header', async () => {
        const r = await signAndVerify(message(['From: ceo@custom.example', 'Subject: hi']));
        assert.equal(r.signingDomain, 'anon.li');
    });

    it('passes when a header line is in the obsolete "Name :" form Haraka does not index', async () => {
        const r = await signAndVerify(message(['From : a@anon.li', 'To: b@example.com', 'Subject: hi']));
        assert.equal(r.status.result, 'pass', r.status.comment);
    });

    it('passes for a large body', async () => {
        const body = 'abcdefghij\r\n'.repeat(1_000_000);
        assert.equal((await signAndVerify(message(['From: a@anon.li', 'Subject: big'], body))).status.result, 'pass');
    });
});

describe('dkim-keys getKey', () => {
    const db = require('../../lib/db');

    it('caches database misses and returns null on lookup errors', async (t) => {
        dkimKeys.clearCache();
        const previous = process.env.LOCAL_DKIM_DIR;
        process.env.LOCAL_DKIM_DIR = path.join(__dirname, 'no-such-dir');
        let calls = 0;
        t.mock.method(db, 'getDkimKey', async (domain) => {
            calls++;
            if (domain === 'broken.example') throw new Error('Unsupported state or unable to authenticate data');
            return null;
        });
        const config = { get: () => ({}) };
        try {
            assert.equal(await dkimKeys.getKey('missing.example', config), null);
            assert.equal(await dkimKeys.getKey('missing.example', config), null);
            assert.equal(calls, 1, 'second miss served from cache');
            assert.equal(await dkimKeys.getKey('broken.example', config), null);
            assert.equal(await dkimKeys.getKey('broken.example', config), null);
            assert.equal(calls, 2, 'lookup errors are cached briefly too');
            assert.equal(await dkimKeys.getKey('../../etc', config), null, 'only plain domain names reach the disk');
        } finally {
            if (previous === undefined) delete process.env.LOCAL_DKIM_DIR;
            else process.env.LOCAL_DKIM_DIR = previous;
            dkimKeys.clearCache();
        }
    });
});
