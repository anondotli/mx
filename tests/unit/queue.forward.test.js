'use strict';

const { describe, it, before, beforeEach, afterEach, mock } = require('node:test');
const assert = require('node:assert/strict');
const { Address } = require('@haraka/email-address');

const { OK, DENY, DENYSOFT, receivedTransaction, readStored } = require('../helpers/haraka');
const queueForward = require('../../plugins/queue.forward');

describe('queue.forward helpers', () => {
    it('prefers Reply-To over From when deriving the original sender', () => {
        const txn = {
            header: {
                get(name) {
                    return {
                        'Reply-To': 'Human Reply <reply@example.com>',
                        'From': 'Envelope Mask <bounce@example.net>',
                    }[name] || null;
                },
            },
            mail_from: { address: 'smtp@example.org' },
        };

        assert.equal(queueForward.getOriginalSenderAddress(txn), 'reply@example.com');
    });

    it('falls back to From when Reply-To is absent', () => {
        const txn = {
            header: {
                get(name) {
                    return {
                        From: 'Visible Sender <from@example.com>',
                    }[name] || null;
                },
            },
            mail_from: { address: 'smtp@example.org' },
        };

        assert.equal(queueForward.getOriginalSenderAddress(txn), 'from@example.com');
    });

    it('falls back to the SMTP envelope sender when headers are missing or invalid', () => {
        const txn = {
            header: {
                get(name) {
                    return {
                        'Reply-To': 'not a valid address header',
                        From: '',
                    }[name] || null;
                },
            },
            mail_from: { address: 'smtp@example.org' },
        };

        assert.equal(queueForward.getOriginalSenderAddress(txn), 'smtp@example.org');
    });

    it('replaces Reply-To while preserving folded headers and raw body bytes', () => {
        const body = Buffer.from([0x00, 0xff, 0x61, 0x62, 0x63, 0x0d, 0x0a]);
        const original = Buffer.concat([
            Buffer.from(
                'From: sender@example.com\r\n' +
                'Reply-To: old@example.com\r\n' +
                '\tOld Name\r\n' +
                'Subject: test\r\n' +
                '\r\n'
            ),
            body,
        ]);

        const updated = queueForward.setRawHeaders(original, [['Reply-To', 'token123@reply.anon.li']]);
        const marker = updated.indexOf('\r\n\r\n');

        assert.notEqual(marker, -1);
        assert.match(updated.subarray(0, marker).toString('utf8'), /Reply-To: token123@reply\.anon\.li/);
        assert.doesNotMatch(updated.subarray(0, marker).toString('utf8'), /old@example\.com|Old Name/);
        assert.deepEqual(updated.subarray(marker + 4), body);
    });

    it('returns the original raw message when no replacement Reply-To is provided', () => {
        const original = Buffer.from(
            'From: sender@example.com\r\n' +
            'Reply-To: old@example.com\r\n' +
            '\r\n' +
            'body\r\n'
        );

        assert.equal(queueForward.setRawHeaders(original, [['Reply-To', null]]), original);
    });

    it('replaces a folded From header without orphaning its continuation lines', () => {
        const original = Buffer.from(
            'From: A Very Long\r\n' +
            '\tDisplay Name <real@dropbox.com>\r\n' +
            'Subject: hi\r\n' +
            '\r\n' +
            'body\r\n'
        );

        const updated = queueForward.setRawHeaders(original, [['From', '"Dropbox via anon.li" <me@anon.li>']]);
        const head = updated.subarray(0, updated.indexOf('\r\n\r\n')).toString('utf8');

        assert.match(head, /From: "Dropbox via anon\.li" <me@anon\.li>/);
        assert.doesNotMatch(head, /real@dropbox\.com|Display Name/);
        assert.match(head, /Subject: hi/);
    });

    it('returns the original raw message when no replacement From is provided', () => {
        const original = Buffer.from('From: sender@example.com\r\n\r\nbody\r\n');
        assert.equal(queueForward.setRawHeaders(original, [['From', null]]), original);
    });
});

describe('queue.forward envelope sender', () => {
    const bounceToken = require('../../lib/bounce-token');

    it('SRS-rewrites a normal sender unchanged', async () => {
        const env = await queueForward.buildEnvelopeSender('alice@example.com', 'secret');
        assert.match(env, /^SRS0=/);
        assert.doesNotThrow(() => new Address(env));
    });

    it('falls back to a short BNC= token when the SRS local-part would exceed 64 octets', async () => {
        bounceToken._clearLocalStore();
        const longSender = 'bounces+108370056-3140-6hvyb0xbfo=anon.li@em6623.email.openai.com';

        // The plain SRS form is what currently blows past the limit.
        const srs = require('../../lib/srs');
        const plainSrs = srs.rewrite(longSender, 'anon.li', 'secret');
        assert.ok(Buffer.byteLength(plainSrs.split('@')[0], 'utf8') > 64);

        const env = await queueForward.buildEnvelopeSender(longSender, 'secret');
        assert.ok(env.startsWith(bounceToken.ADDRESS_PREFIX));
        assert.ok(Buffer.byteLength(env.split('@')[0], 'utf8') <= 64);
        // Must be parseable by the constructor that threw on the over-length SRS.
        assert.doesNotThrow(() => new Address(env));

        // And the token resolves back to the original sender for bounce routing.
        const token = env.split('@')[0].slice(bounceToken.ADDRESS_PREFIX.length);
        const decoded = await bounceToken.decode(token);
        assert.equal(decoded.originalSender, longSender);
        assert.equal(decoded.relay, false, 'bounces for forwarded mail are never relayed');
    });

    it('returns null for a null sender (<>) instead of throwing', async () => {
        assert.equal(await queueForward.buildEnvelopeSender(null, 'secret'), null);
        assert.equal(await queueForward.buildEnvelopeSender('', 'secret'), null);
    });
});

describe('queue.forward From munging of encoded display names', () => {
    it('decodes an RFC 2047 display name instead of quoting the encoded-word', () => {
        const txn = {
            header: {
                get: () => '=?UTF-8?B?w6ltaWxl?= <e@x.example>',
                get_decoded: () => 'émile <e@x.example>',
            },
        };
        const from = queueForward.buildMungedFrom(txn, 'alias@anon.li');
        assert.equal(from, `=?UTF-8?B?${Buffer.from('émile via anon.li').toString('base64')}?= <alias@anon.li>`);
    });
});

describe('queue.forward From munging', () => {
    const txnWith = (policy, fromHeader, result = 'pass') => ({
        notes: { mailauth: { dmarc: { policy, status: { result } } } },
        header: { get: name => (name === 'From' ? fromHeader : null) },
    });

    it('munges only when the sender publishes reject or quarantine', () => {
        assert.equal(queueForward.shouldMungeFrom(txnWith('reject')), true);
        assert.equal(queueForward.shouldMungeFrom(txnWith('quarantine')), true);
        assert.equal(queueForward.shouldMungeFrom(txnWith('none')), false);
        assert.equal(queueForward.shouldMungeFrom({ notes: {} }), false);
        assert.equal(queueForward.shouldMungeFrom({}), false);
    });

    it('never munges mail that failed DMARC, which would sign a forged sender', () => {
        assert.equal(queueForward.shouldMungeFrom(txnWith('reject', null, 'fail')), false);
        assert.equal(queueForward.shouldMungeFrom(txnWith('quarantine', null, 'fail')), false);
        assert.equal(queueForward.shouldMungeFrom(txnWith('quarantine', null, 'temperror')), false);
        assert.equal(queueForward.shouldMungeFrom({ notes: { mailauth: { dmarc: { policy: 'reject' } } } }), false);
    });

    it('keeps the sender display name and points the address at the alias', () => {
        const txn = txnWith('reject', 'Dropbox <no-reply@dropbox.com>');
        assert.equal(
            queueForward.buildMungedFrom(txn, 'me@anon.li'),
            '"Dropbox via anon.li" <me@anon.li>'
        );
    });

    it('falls back to a generic display name when From has no phrase', () => {
        const txn = txnWith('reject', 'no-reply@dropbox.com');
        assert.equal(
            queueForward.buildMungedFrom(txn, 'me@anon.li'),
            '"no-reply@dropbox.com via anon.li" <me@anon.li>'
        );
    });

    it('RFC 2047 encodes non-ASCII display names so the header stays 7-bit', () => {
        const txn = txnWith('reject', '"Naïve Sender" <x@dropbox.com>');
        const from = queueForward.buildMungedFrom(txn, 'me@anon.li');

        assert.match(from, /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?= <me@anon\.li>$/);
        // eslint-disable-next-line no-control-regex
        assert.match(from, /^[\x00-\x7F]*$/);
        const b64 = from.match(/\?B\?([^?]+)\?=/)[1];
        assert.equal(Buffer.from(b64, 'base64').toString('utf8'), 'Naïve Sender via anon.li');
    });

    it('quotes and escapes special characters in ASCII display names', () => {
        const txn = txnWith('quarantine', '"Quote \\" Co." <x@dropbox.com>');
        assert.equal(
            queueForward.buildMungedFrom(txn, 'me@anon.li'),
            '"Quote \\" Co. via anon.li" <me@anon.li>'
        );
    });
});

// Regression for a Tuta user's "emails landing incomplete" report: Discord IP-verification
// mail (a multipart/alternative with the verify button in the text/html part) was arriving
// with "a major missing part." The plain forward path rewrites Reply-To and From over
// the raw message with setRawHeaders (queue.forward.js prepareCopy), so those
// header rewrites must touch *only* the header block and leave every MIME part byte-for-byte.
describe('queue.forward preserves the full body when rewriting headers', () => {
    const boundary = 'b=_discord_4f2a1c';
    const verifyUrl = 'https://discord.com/verify?token=abc123';

    // A realistic multipart/alternative message. The body deliberately contains its own
    // blank lines (\r\n\r\n between each part's headers and content) to prove the header
    // rewriters split on the *first* end-of-headers marker, not a later one in the body.
    const body = Buffer.from(
        `--${boundary}\r\n` +
        'Content-Type: text/plain; charset=utf-8\r\n' +
        '\r\n' +
        'New login location detected.\r\n' +
        `Verify: ${verifyUrl}\r\n` +
        '\r\n' +
        `--${boundary}\r\n` +
        'Content-Type: text/html; charset=utf-8\r\n' +
        '\r\n' +
        '<html><body><h1>Hey there!</h1>' +
        '<p>We detected a login from a new IP address.</p>' +
        `<a href="${verifyUrl}" style="background:#5865F2;color:#fff;">Verify Login</a>` +
        '<img src="https://cdn.discordapp.com/assets/logo.png" width="120" height="40">' +
        '</body></html>\r\n' +
        '\r\n' +
        `--${boundary}--\r\n`
    );

    const original = Buffer.concat([
        Buffer.from(
            'From: Discord <noreply@discord.com>\r\n' +
            'To: alias@anon.li\r\n' +
            'Subject: New login location detected\r\n' +
            'Reply-To: noreply@discord.com\r\n' +
            'Message-ID: <abc123@discord.com>\r\n' +
            `Content-Type: multipart/alternative; boundary="${boundary}"\r\n` +
            'MIME-Version: 1.0\r\n' +
            '\r\n'
        ),
        body,
    ]);

    it('keeps both MIME parts and the verify link intact through Reply-To + From munging', () => {
        const replyTo = 'tok_deadbeef@reply.anon.li';
        // Discord publishes a strict DMARC policy, so the real forward path munges From.
        const mungedFrom = queueForward.buildMungedFrom(
            {
                notes: { mailauth: { dmarc: { policy: 'quarantine' } } },
                header: { get: name => (name === 'From' ? 'Discord <noreply@discord.com>' : null) },
            },
            'alias@anon.li'
        );

        const forwarded = queueForward.setRawHeaders(original, [
            ['Reply-To', replyTo],
            ['From', mungedFrom],
        ]);

        const marker = forwarded.indexOf('\r\n\r\n');
        assert.notEqual(marker, -1);
        const head = forwarded.subarray(0, marker).toString('utf8');
        const fwdBody = forwarded.subarray(marker + 4);

        // The entire body — both alternatives, the boundary, the verify link — is untouched.
        assert.deepEqual(fwdBody, body);

        const bodyStr = fwdBody.toString('utf8');
        assert.ok(bodyStr.includes('Content-Type: text/plain'), 'text/plain part survives');
        assert.ok(bodyStr.includes('Content-Type: text/html'), 'text/html part survives');
        assert.ok(bodyStr.includes(verifyUrl), 'verify URL survives');
        assert.ok(bodyStr.includes('>Verify Login</a>'), 'verify button survives');
        assert.ok(bodyStr.includes(`--${boundary}--`), 'closing boundary survives');

        // Exactly one From and one Reply-To remain, both rewritten; the multipart
        // Content-Type stays in the header block so the body is still parseable.
        const headerLines = head.split('\r\n');
        assert.equal(headerLines.filter(l => /^From:/i.test(l)).length, 1);
        assert.equal(headerLines.filter(l => /^Reply-To:/i.test(l)).length, 1);
        assert.match(head, /From: "Discord via anon\.li" <alias@anon\.li>/);
        assert.match(head, /Reply-To: tok_deadbeef@reply\.anon\.li/);
        assert.doesNotMatch(head, /noreply@discord\.com/);
        assert.match(head, new RegExp(`Content-Type: multipart/alternative; boundary="${boundary}"`));
    });
});

// ── End-to-end through the plugin with real Haraka transactions ─────────

const path = require('node:path');
const bounceToken = require('../../lib/bounce-token');
const replyToken = require('../../lib/reply-token');
const harakaTransaction = require(path.join(__dirname, '../../node_modules/haraka/transaction'));
const db = require('../../lib/db');

// No database in unit tests: alias stats are fire-and-forget.
before(() => mock.method(db, 'incrementAliasStats', async () => {}));

function setup() {
    const queued = [];
    const outbound = {
        send_trans_email(txn, next) {
            queued.push(txn);
            next(OK, 'queued');
        },
    };
    queueForward.register.call({
        haraka_require(name) {
            if (name === 'outbound') return outbound;
            if (name === 'transaction') return harakaTransaction;
            throw new Error(`unexpected haraka_require(${name})`);
        },
        config: { get: () => ({}) },
        register_hook() {},
    });
    const logs = { info: [], warn: [], error: [] };
    const plugin = {
        loginfo: (m) => logs.info.push(String(m)),
        logwarn: (m) => logs.warn.push(String(m)),
        logerror: (m) => logs.error.push(String(m)),
    };
    async function run(txn) {
        return new Promise((resolve, reject) => {
            queueForward.process_forward.call(plugin, (code, msg) => resolve({ code, msg }), { transaction: txn })
                .catch(reject);
        });
    }
    return { queued, outbound, plugin, logs, run };
}

// Bytes exactly as Haraka writes them to the queue file and sends after DATA.
const queueFileBytes = (txn) => readStored(txn, { dot_stuffed: false });

const alias = (recipients, email = 'shop@anon.li') => ({ id: 'alias-1', email, recipients });

describe('queue.forward forward mode', () => {
    let previousSecret;
    beforeEach(() => {
        previousSecret = process.env.MAIL_API_SECRET;
        process.env.MAIL_API_SECRET = 'secret';
        bounceToken._clearLocalStore();
        replyToken._clearLocalStore();
    });
    afterEach(() => {
        process.env.MAIL_API_SECRET = previousSecret;
    });

    const inbound = (body, extraHeaders = []) => Buffer.concat([
        Buffer.from([
            'From: Shop <news@shop.example>',
            'To: shop@anon.li',
            'Subject: Weekly',
            'Message-ID: <m1@shop.example>',
            ...extraHeaders,
            '',
            '',
        ].join('\r\n')),
        Buffer.isBuffer(body) ? body : Buffer.from(body),
    ]);

    it('queues a dot-stuffed, byte-exact copy (a lone "." no longer truncates the message)', async () => {
        const { queued, run } = setup();
        const body = Buffer.concat([
            Buffer.from('<style>\r\n.button { color: red }\r\n</style>\r\n.\r\nafter the lone dot '),
            Buffer.from([0x63, 0x61, 0x66, 0xe9]), // "café" in ISO-8859-1
            Buffer.from('\r\n'),
        ]);
        const txn = await receivedTransaction(inbound(body), {
            notes: { alias: alias([{ email: 'me@example.net', pgpPublicKey: null }]) },
            mailFrom: new Address('news@shop.example'),
        });

        const result = await run(txn);
        assert.equal(result.code, OK);
        assert.equal(queued.length, 1);

        const wire = await queueFileBytes(queued[0]);
        assert.ok(wire.includes(Buffer.from('\r\n..button { color: red }\r\n')), 'leading dot is stuffed');
        assert.ok(wire.includes(Buffer.from('\r\n..\r\nafter the lone dot ')), 'lone dot is stuffed');
        assert.ok(wire.includes(Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x0d, 0x0a])), '8-bit bytes preserved');

        const delivered = await readStored(queued[0]);
        assert.ok(delivered.includes(Buffer.from('\r\n.button { color: red }\r\n</style>\r\n.\r\nafter the lone dot ')));
    });

    it('rewrites the envelope with SRS, sets a per-recipient reply token and tags the copy', async () => {
        const { queued, run } = setup();
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([{ email: 'me@example.net', pgpPublicKey: null }]) },
            mailFrom: new Address('news@shop.example'),
        });

        assert.equal((await run(txn)).code, OK);
        const copy = queued[0];
        assert.match(copy.mail_from.address, /^SRS0=.*@anon\.li$/);
        assert.equal(copy.rcpt_to[0].address, 'me@example.net');
        assert.deepEqual(copy.notes.forward, { aliasId: 'alias-1', aliasEmail: 'shop@anon.li' });
        assert.equal(copy.notes.dkim_domain, undefined);

        const replyTo = copy.header.get('Reply-To').trim();
        assert.match(replyTo, /^[A-Za-z0-9_-]+@reply\.anon\.li$/);
        const decoded = await replyToken.decode(replyTo.split('@')[0]);
        assert.deepEqual(decoded, {
            originalSender: 'news@shop.example',
            aliasEmail: 'shop@anon.li',
            recipientEmail: 'me@example.net',
        });
        assert.equal(copy.header.get('X-Anon-Forward').trim(), 'true');
        assert.equal(copy.header.get('From').trim(), 'Shop <news@shop.example>');
    });

    it('forwards mail with a null envelope sender (DSNs) instead of tempfailing forever', async () => {
        const { queued, run } = setup();
        const txn = await receivedTransaction(inbound('Delivery report\r\n'), {
            notes: { alias: alias([{ email: 'me@example.net', pgpPublicKey: null }]) },
            mailFrom: new Address('<>'),
        });

        assert.equal((await run(txn)).code, OK);
        assert.equal(queued[0].mail_from.isNull(), true);
    });

    it('munges From for strict-DMARC senders and signs custom-domain aliases with their own key', async (t) => {
        const dkimKeys = require('../../lib/dkim-keys');
        dkimKeys.clearCache();
        t.mock.method(db, 'getDkimKey', async (domain) => (domain === 'custom.example' ? { privateKey: 'PEM', selector: 'default' } : null));
        const { queued, run } = setup();
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: {
                alias: alias([{ email: 'me@example.net', pgpPublicKey: null }], 'shop@custom.example'),
                mailauth: { dmarc: { policy: 'reject', status: { result: 'pass' } } },
            },
            mailFrom: new Address('news@shop.example'),
        });

        assert.equal((await run(txn)).code, OK);
        const copy = queued[0];
        assert.equal(copy.header.get('From').trim(), '"Shop via anon.li" <shop@custom.example>');
        assert.equal(copy.notes.dkim_domain, 'custom.example');
        dkimKeys.clearCache();
    });

    it('munges From onto the reply address when the custom domain has no usable DKIM key', async (t) => {
        const dkimKeys = require('../../lib/dkim-keys');
        dkimKeys.clearCache();
        t.mock.method(db, 'getDkimKey', async () => null);
        const { queued, run } = setup();
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: {
                alias: alias([{ email: 'me@example.net', pgpPublicKey: null }], 'shop@nokey.example'),
                mailauth: { dmarc: { policy: 'reject', status: { result: 'pass' } } },
            },
            mailFrom: new Address('news@shop.example'),
        });

        assert.equal((await run(txn)).code, OK);
        const copy = queued[0];
        const replyTo = copy.header.get('Reply-To').trim();
        assert.match(replyTo, /@reply\.anon\.li$/);
        assert.equal(copy.header.get('From').trim(), `"Shop via anon.li" <${replyTo}>`, 'aligns with the anon.li signature');
        assert.equal(copy.notes.dkim_domain, undefined);
        dkimKeys.clearCache();
    });

    it('removes trackers from the forwarded copy only, leaving the received message intact', async () => {
        const { queued, run } = setup();
        const html = '<a href="https://example.com/?id=1&amp;utm_source=n">x</a>\r\n';
        const raw = inbound(html, ['MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8']);
        const txn = await receivedTransaction(raw, {
            notes: { alias: alias([{ email: 'me@example.net', pgpPublicKey: null }]) },
            mailFrom: new Address('news@shop.example'),
        });

        assert.equal((await run(txn)).code, OK);
        const copy = (await readStored(queued[0])).toString('utf8');
        assert.match(copy, /href="https:\/\/example\.com\/\?id=1"/);
        assert.match(copy, /^X-Privacy: Tracking-Removed$/m);
        assert.match((await readStored(txn)).toString('utf8'), /utm_source=n/, 'inbound message untouched for authentication');
    });

    it('delivers to the remaining recipients when one copy cannot be queued', async () => {
        const { queued, run, logs } = setup();
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([
                { email: 'not a valid address', pgpPublicKey: null },
                { email: 'me@example.net', pgpPublicKey: null },
            ]) },
            mailFrom: new Address('news@shop.example'),
        });

        assert.equal((await run(txn)).code, OK);
        assert.deepEqual(queued.map(t => t.rcpt_to[0].address), ['me@example.net']);
        assert.equal(logs.error.length, 1);
        assert.match(logs.error[0], /Skipping recipient 1\/2 of .*: invalid address/);
        assert.match(logs.info.join('\n'), /Forwarded \S+-1 to recipient 2\/2/);
    });

    it('never logs a recipient\'s real address (the log would map aliases to mailboxes)', async () => {
        const { run, logs } = setup();
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([
                { email: 'not a valid address', pgpPublicKey: null },
                { email: 'other@anon.li', pgpPublicKey: null },
                { email: 'me@example.net', pgpPublicKey: 'not a key' },
            ]) },
            mailFrom: new Address('news@shop.example'),
        });

        assert.equal((await run(txn)).code, OK);
        const all = [...logs.info, ...logs.warn, ...logs.error].join('\n');
        assert.doesNotMatch(all, /not a valid address|other@anon\.li|me@example\.net/);
    });

    it('tempfails without queueing anything when one recipient\'s reply token fails (no duplicates on retry)', async (t) => {
        const { queued, run } = setup();
        const realCreate = replyToken.create;
        t.mock.method(replyToken, 'create', async (sender, aliasEmail, recipient) => {
            if (recipient === 'b@example.net') throw new Error('redis blip');
            return realCreate(sender, aliasEmail, recipient);
        });
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([
                { email: 'a@example.net', pgpPublicKey: null },
                { email: 'b@example.net', pgpPublicKey: null },
            ]) },
            mailFrom: new Address('news@shop.example'),
        });

        assert.equal((await run(txn)).code, DENYSOFT);
        assert.equal(queued.length, 0);
    });

    it('rejects when no recipient address is deliverable (a retry cannot help)', async () => {
        const { queued, run } = setup();
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([{ email: 'not a valid address', pgpPublicKey: null }]) },
            mailFrom: new Address('news@shop.example'),
        });
        const result = await run(txn);
        assert.equal(result.code, DENY);
        assert.equal(queued.length, 0);
    });

    it('never queues a recipient on an alias domain (a forwarding loop)', async () => {
        const { queued, run, logs } = setup();
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([
                { email: 'other@anon.li', pgpPublicKey: null },
                { email: 'me@example.net', pgpPublicKey: null },
            ]) },
            mailFrom: new Address('news@shop.example'),
        });
        assert.equal((await run(txn)).code, OK);
        assert.deepEqual(queued.map(q => q.rcpt_to[0].address), ['me@example.net']);
        assert.match(logs.error.join('\n'), /alias domains cannot be recipients/);
    });

    it('tempfails when any copy fails to queue, so no recipient silently misses the message', async () => {
        const { outbound, run } = setup();
        const realSend = outbound.send_trans_email;
        outbound.send_trans_email = (txn, next) => {
            if (txn.rcpt_to[0].address === 'b@example.net') return next(DENYSOFT, 'disk full');
            return realSend(txn, next);
        };
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([
                { email: 'a@example.net', pgpPublicKey: null },
                { email: 'b@example.net', pgpPublicKey: null },
            ]) },
            mailFrom: new Address('news@shop.example'),
        });
        assert.equal((await run(txn)).code, DENYSOFT);
    });

    it('still forwards when tracking removal fails', async (t) => {
        const trackingRemove = require('../../lib/tracking-remove');
        t.mock.method(trackingRemove, 'removeTracking', async () => { throw new Error('parser exploded'); });
        const { queued, run, logs } = setup();
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([{ email: 'me@example.net', pgpPublicKey: null }]) },
            mailFrom: new Address('news@shop.example'),
        });
        assert.equal((await run(txn)).code, OK);
        assert.equal(queued.length, 1);
        assert.match(logs.warn.join('\n'), /Tracking removal skipped/);
    });

    it('tempfails when no copy could be queued, e.g. the reply-token store is down', async (t) => {
        const { queued, run } = setup();
        t.mock.method(replyToken, 'create', async () => { throw new Error('redis down'); });
        const txn = await receivedTransaction(inbound('Hello\r\n'), {
            notes: { alias: alias([{ email: 'me@example.net', pgpPublicKey: null }]) },
            mailFrom: new Address('news@shop.example'),
        });

        const result = await run(txn);
        assert.equal(result.code, DENYSOFT);
        assert.equal(queued.length, 0, 'never forwarded without a reply token (would expose the recipient)');
    });
});

describe('queue.forward PGP copies', () => {
    const openpgp = require('openpgp');

    it('encrypts for recipients with a key and marks plaintext fallbacks', async () => {
        const { publicKey, privateKey } = await openpgp.generateKey({
            type: 'ecc', curve: 'curve25519', userIDs: [{ email: 'me@example.net' }], format: 'armored',
        });
        const { queued, run, logs } = setup();
        const raw = 'From: a@shop.example\r\nTo: shop@anon.li\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\n.secret line\r\n';
        const txn = await receivedTransaction(raw, {
            notes: { alias: alias([
                { email: 'me@example.net', pgpPublicKey: publicKey },
                { email: 'other@example.net', pgpPublicKey: 'not a key' },
            ]) },
            mailFrom: new Address('a@shop.example'),
        });

        assert.equal((await run(txn)).code, OK);
        const byRcpt = Object.fromEntries(queued.map(q => [q.rcpt_to[0].address, q]));

        const encrypted = (await readStored(byRcpt['me@example.net'])).toString('utf8');
        assert.match(encrypted, /multipart\/encrypted/);
        assert.match(encrypted, /^Reply-To: .*@reply\.anon\.li$/m);
        const armored = encrypted.slice(encrypted.indexOf('-----BEGIN PGP MESSAGE-----'), encrypted.indexOf('-----END PGP MESSAGE-----') + 25);
        const { data } = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: armored }),
            decryptionKeys: await openpgp.readPrivateKey({ armoredKey: privateKey }),
        });
        assert.match(data, /\.secret line/);

        const plain = (await readStored(byRcpt['other@example.net'])).toString('utf8');
        assert.match(plain, /^X-PGP-Encryption-Failed: true$/m);
        assert.match(plain, /\.secret line/);
        assert.equal(logs.warn.length, 1);
    });
});

describe('queue.forward reply mode', () => {
    beforeEach(() => bounceToken._clearLocalStore());

    const userReply = [
        'Received: from mail-wr1.provider.example (mail-wr1.provider.example [203.0.113.9])',
        '\tby mx.anon.li (Haraka) with ESMTPS id ABC',
        '\tenvelope-from <real.person@provider.example>;',
        '\tThu, 1 Jan 2026 00:00:00 +0000',
        'Received-SPF: pass (mx.anon.li: domain of real.person@provider.example designates 203.0.113.9 as permitted sender) envelope-from=real.person@provider.example',
        'Authentication-Results: mx.anon.li; spf=pass smtp.mailfrom=real.person@provider.example',
        'DKIM-Signature: v=1; a=rsa-sha256; d=provider.example; i=real.person@provider.example; s=x; b=abc',
        'From: Real Person <real.person@provider.example>',
        'Sender: real.person@provider.example',
        'Reply-To: real.person@provider.example',
        'Disposition-Notification-To: real.person@provider.example',
        'X-Originating-IP: [198.51.100.7]',
        'X-Originating-IP : [198.51.100.7]',
        'X-Junk-without-colon 198.51.100.7',
        'Autocrypt: addr=real.person@provider.example; keydata=xyz',
        'To: tok123@reply.anon.li',
        'Cc: someone@else.example',
        'Subject: Re: Weekly',
        'Date: Thu, 1 Jan 2026 09:00:00 +0900',
        'Message-ID: <abc@real-laptop.provider.example>',
        'In-Reply-To: <m1@shop.example>',
        'References: <m1@shop.example>',
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Thanks!',
        '',
    ].join('\r\n');

    it('sends only allowlisted headers, as the alias, to the original sender', async () => {
        const { queued, run } = setup();
        const txn = await receivedTransaction(userReply, {
            notes: { reply: { originalSender: 'news@shop.example', aliasEmail: 'shop@anon.li', recipientEmail: 'real.person@provider.example' } },
            mailFrom: new Address('real.person@provider.example'),
        });

        assert.equal((await run(txn)).code, OK);
        const sent = queued[0];
        const head = (await readStored(sent)).toString('utf8').split('\r\n\r\n')[0];

        assert.doesNotMatch(head, /real\.person|provider\.example|203\.0\.113|198\.51\.100|\+0900|someone@else/);
        assert.match(head, /^From: shop@anon\.li$/m);
        assert.match(head, /^To: news@shop\.example$/m);
        assert.match(head, /^Subject: Re: Weekly$/m);
        assert.match(head, /^In-Reply-To: <m1@shop\.example>$/m);
        assert.match(head, /^Content-Type: text\/plain; charset=utf-8$/m);

        assert.equal(sent.rcpt_to[0].address, 'news@shop.example');
        const envelope = sent.mail_from.address;
        assert.ok(envelope.startsWith(bounceToken.ADDRESS_PREFIX));
        const bounce = await bounceToken.decode(envelope.split('@')[0].slice(bounceToken.ADDRESS_PREFIX.length));
        assert.deepEqual(bounce, { originalSender: 'shop@anon.li', relay: true },
            'a bounced reply goes back through the alias');
        assert.equal(sent.notes.dkim_domain, undefined);
    });

    it('replaces the client Message-ID and maps it in later replies and forwards', async () => {
        const messageIds = require('../../lib/message-ids');
        messageIds._clearLocalStore();
        const { queued, run } = setup();
        const replyNotes = () => ({ reply: { originalSender: 'news@shop.example', aliasEmail: 'shop@anon.li', recipientEmail: 'real.person@provider.example' } });

        // First reply: client ID <abc@real-laptop.provider.example>
        const first = await receivedTransaction(userReply, { notes: replyNotes(), mailFrom: new Address('real.person@provider.example') });
        assert.equal((await run(first)).code, OK);
        const publicId = queued[0].header.get('Message-ID').trim();
        assert.match(publicId, /^<[A-Za-z0-9_-]{32}@anon\.li>$/);

        // Follow-up reply references the user's own earlier (client) ID
        const followUp = userReply
            .replace('Message-ID: <abc@real-laptop.provider.example>', 'Message-ID: <def@real-laptop.provider.example>')
            .replace('References: <m1@shop.example>', 'References: <m1@shop.example>\r\n <abc@real-laptop.provider.example>')
            .replace('In-Reply-To: <m1@shop.example>', 'In-Reply-To: <abc@real-laptop.provider.example>');
        const second = await receivedTransaction(followUp, { notes: replyNotes(), mailFrom: new Address('real.person@provider.example') });
        assert.equal((await run(second)).code, OK);
        const head = (await readStored(queued[1])).toString('utf8').split('\r\n\r\n')[0];
        assert.doesNotMatch(head, /provider\.example/);
        assert.equal(queued[1].header.get('In-Reply-To').trim(), publicId);
        assert.match(queued[1].header.get('References'), new RegExp(`<m1@shop\\.example>\\s+${publicId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));

        // The correspondent answers the public ID; the user's copy threads on their own ID
        const answer = [
            'From: Shop <news@shop.example>', 'To: shop@anon.li', 'Subject: Re: Re: Weekly',
            `In-Reply-To: ${publicId}`, `References: <m1@shop.example> ${publicId}`, '', 'ok', '',
        ].join('\r\n');
        const fwd = await receivedTransaction(answer, {
            notes: { alias: alias([{ email: 'real.person@provider.example', pgpPublicKey: null }]) },
            mailFrom: new Address('news@shop.example'),
        });
        assert.equal((await run(fwd)).code, OK);
        const copy = queued[2];
        assert.equal(copy.header.get('In-Reply-To').trim(), '<abc@real-laptop.provider.example>');
        assert.equal(copy.header.get('References').trim(), '<m1@shop.example> <abc@real-laptop.provider.example>');

        // The same public ID reaching a different alias (e.g. the reply went to
        // another anon.li user) must not be mapped back to the client ID
        const elsewhere = await receivedTransaction(answer.replace('To: shop@anon.li', 'To: other@anon.li'), {
            notes: { alias: alias([{ email: 'someone@example.org', pgpPublicKey: null }], 'other@anon.li') },
            mailFrom: new Address('news@shop.example'),
        });
        assert.equal((await run(elsewhere)).code, OK);
        assert.equal(queued[3].header.get('In-Reply-To').trim(), publicId);
        assert.doesNotMatch(queued[3].header.get('References'), /provider\.example/);
    });

    it('signs replies from custom-domain aliases with that domain', async () => {
        const { queued, run } = setup();
        const txn = await receivedTransaction(userReply, {
            notes: { reply: { originalSender: 'news@shop.example', aliasEmail: 'me@custom.example', recipientEmail: 'real.person@provider.example' } },
            mailFrom: new Address('real.person@provider.example'),
        });
        assert.equal((await run(txn)).code, OK);
        assert.equal(queued[0].notes.dkim_domain, 'custom.example');
    });
});

describe('queue.forward bounce mode', () => {
    const dsn = 'From: MAILER-DAEMON@provider.example\r\nSubject: Undelivered\r\n\r\nFinal-Recipient: rfc822; real.person@provider.example\r\n';

    it('drops bounces for forwarded mail instead of exposing the recipient', async () => {
        const { queued, run } = setup();
        const txn = await receivedTransaction(dsn, {
            notes: { bounce: { originalSender: 'news@shop.example', relay: false } },
            mailFrom: new Address('<>'),
        });
        assert.equal((await run(txn)).code, OK);
        assert.equal(queued.length, 0);
    });

    it('relays bounced replies back to the alias with a null sender', async () => {
        const { queued, run } = setup();
        const txn = await receivedTransaction(dsn, {
            notes: { bounce: { originalSender: 'shop@anon.li', relay: true } },
            mailFrom: new Address('<>'),
        });
        await run(txn);
        assert.equal(queued.length, 1);
        assert.equal(queued[0].mail_from.isNull(), true);
        assert.equal(queued[0].rcpt_to[0].address, 'shop@anon.li');
    });
});

describe('queue.forward Purelymail relay', () => {
    let previousSecret;
    beforeEach(() => {
        previousSecret = process.env.MAIL_API_SECRET;
        process.env.MAIL_API_SECRET = 'secret';
        bounceToken._clearLocalStore();
    });
    afterEach(() => {
        process.env.MAIL_API_SECRET = previousSecret;
    });

    it('relays with a stateless SRS return path, storing nothing per message', async (t) => {
        t.mock.method(bounceToken, 'create', async () => assert.fail('nothing stored for SRS-sized senders'));
        const { queued, run } = setup();
        const txn = await receivedTransaction('Subject: hi\r\n\r\nbody\r\n', {
            notes: { purelymail_relay: true, purelymail_recipient: 'hi@anon.li' },
            mailFrom: new Address('sender@example.com'),
        });

        assert.equal((await run(txn)).code, OK);
        const relayed = queued[0];
        assert.equal(relayed.notes.purelymail_mx, true);
        assert.equal(relayed.notes.purelymail_original_sender, 'sender@example.com');
        assert.match(relayed.mail_from.address, /^SRS0=.*@anon\.li$/);
        assert.deepEqual(relayed.rcpt_to.map(r => r.address), ['hi@anon.li']);
    });

    it('uses a short bounce token for long ESP senders before relaying to Purelymail', async () => {
        const sender = 'bounces+10329420-d952-hi=anon.li@em2372.brandfetch.co';
        const { queued, run } = setup();
        const txn = await receivedTransaction('Subject: hi\r\n\r\nbody\r\n', {
            notes: { purelymail_relay: true, purelymail_recipient: 'hi@anon.li' },
            mailFrom: new Address(sender),
        });

        assert.equal((await run(txn)).code, OK);
        const env = queued[0].mail_from.address;
        assert.ok(env.startsWith(bounceToken.ADDRESS_PREFIX));
        assert.ok(Buffer.byteLength(env.split('@')[0], 'utf8') <= 64);
        const decoded = await bounceToken.decode(env.split('@')[0].slice(bounceToken.ADDRESS_PREFIX.length));
        assert.equal(decoded.originalSender, sender);
    });

    it('DENYSOFTs Purelymail relay errors instead of throwing out of the hook', async (t) => {
        t.mock.method(bounceToken, 'create', async () => { throw new Error('redis down'); });
        const { queued, run } = setup();
        const txn = await receivedTransaction('Subject: hi\r\n\r\nbody\r\n', {
            notes: { purelymail_relay: true, purelymail_recipient: 'hi@anon.li' },
            mailFrom: new Address('bounces+10329420-d952-hi=anon.li@em2372.brandfetch.co'),
        });

        const result = await run(txn);
        assert.equal(result.code, DENYSOFT);
        assert.equal(result.msg, 'Forwarding error');
        assert.equal(queued.length, 0);
    });
});

describe('queue.forward outbound bounce hook', () => {
    const plugin = { loginfo() {} };
    const bounceWith = (notes) => {
        const hmail = { todo: { notes, mail_from: new Address('SRS0=x=AA=shop.example=news@anon.li') } };
        let code;
        queueForward.handle_bounce.call(plugin, (c) => { code = c; }, hmail, new Error('550 no such user'));
        return { code, hmail };
    };

    it('suppresses DSNs for forwarded copies (they name the real recipient)', () => {
        assert.equal(bounceWith({ forward: { aliasEmail: 'shop@anon.li' } }).code, OK);
    });

    it('logs only the SMTP status of a failed forward, never the reply text', () => {
        const status = (err) => queueForward.smtpStatus(err);
        assert.equal(status(new Error('550 5.1.1 <me@example.net>: Recipient address rejected')), '550 5.1.1');
        assert.equal(status('550 Mailbox unavailable'), '550');
        // Haraka's message for an RCPT rejection lists the addresses; the status
        // comes from the recipient's DSN fields instead
        const rejected = Object.assign(new Error('Some recipients failed: me@example.net'), {
            bounced_rcpt: [{ dsn_smtp_code: '550', dsn_status: '5.1.1' }],
        });
        assert.equal(status(rejected), '550 5.1.1');
        assert.equal(status(new Error('Some recipients failed: me@example.net')), 'no SMTP status');
        assert.equal(status(new Error('Too many failures (Tried all MXs example.net)')), 'no SMTP status');
    });

    it('sends DSNs for replies straight to the alias', () => {
        const { code, hmail } = bounceWith({ reply: { aliasEmail: 'shop@anon.li', recipientEmail: 'me@example.net' } });
        assert.equal(code, undefined);
        assert.equal(hmail.todo.mail_from.address, 'shop@anon.li');
    });

    it('sends Purelymail relay DSNs straight to the original sender, and none for null senders', () => {
        const relayed = bounceWith({ purelymail_relay: true, purelymail_original_sender: 'someone@example.com' });
        assert.equal(relayed.code, undefined);
        assert.equal(relayed.hmail.todo.mail_from.address, 'someone@example.com');
        assert.equal(bounceWith({ purelymail_relay: true }).code, OK);
    });

    it('leaves other bounces to Haraka', () => {
        const { code, hmail } = bounceWith({});
        assert.equal(code, undefined);
        assert.match(hmail.todo.mail_from.address, /^SRS0=/);
    });
});

// Haraka core reads envelope addresses as @haraka/email-address objects
// (`address` is a getter). An address from another library would reach the
// queue file, the SMTP envelope and DSNs as its method's source text.
describe('queue.forward envelope addresses are Haraka\'s own class', () => {
    beforeEach(() => {
        process.env.MAIL_API_SECRET = 'secret';
    });

    const assertHarakaAddresses = (txn) => {
        assert.ok(txn.mail_from instanceof Address, 'mail_from');
        for (const rcpt of txn.rcpt_to) assert.ok(rcpt instanceof Address, 'rcpt_to');
    };
    const modes = {
        forward: { notes: { alias: alias([{ email: 'me@example.net', pgpPublicKey: null }]) }, mailFrom: 'news@shop.example' },
        reply: { notes: { reply: { originalSender: 'news@shop.example', aliasEmail: 'shop@anon.li', recipientEmail: 'me@example.net' } }, mailFrom: 'me@example.net' },
        'bounce relay': { notes: { bounce: { originalSender: 'shop@anon.li', relay: true } }, mailFrom: '<>' },
        'Purelymail relay': { notes: { purelymail_relay: true, purelymail_recipient: 'hi@anon.li' }, mailFrom: 'sender@example.com' },
    };

    for (const [mode, { notes, mailFrom }] of Object.entries(modes)) {
        it(`in ${mode} mode`, async () => {
            const { queued, run } = setup();
            const txn = await receivedTransaction('Subject: hi\r\n\r\nbody\r\n', { notes, mailFrom: new Address(mailFrom) });
            assert.equal((await run(txn)).code, OK);
            assert.equal(queued.length, 1);
            assertHarakaAddresses(queued[0]);
        });
    }

    it('in the DSN return path set by the bounce hook', () => {
        const hmail = { todo: { notes: { reply: { aliasEmail: 'shop@anon.li' } }, mail_from: new Address('<x@anon.li>') } };
        queueForward.handle_bounce.call({ loginfo() {} }, () => {}, hmail, new Error('550'));
        assert.ok(hmail.todo.mail_from instanceof Address);
        assert.equal(hmail.todo.mail_from.address, 'shop@anon.li');
    });
});

describe('forwarded copy authentication (queue.forward → arc.sign → dkim.custom)', () => {
    const crypto = require('node:crypto');
    const fs = require('node:fs');
    const os = require('node:os');
    const { authenticate } = require('mailauth');
    const arcSign = require('../../plugins/arc.sign');
    const dkimCustom = require('../../plugins/dkim.custom');

    it('produces DKIM and ARC signatures that verify, for a folded multipart message', async () => {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const keyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'anonli-dkim-'));
        fs.mkdirSync(path.join(keyDir, 'anon.li'));
        fs.writeFileSync(path.join(keyDir, 'anon.li', 'private'), privateKey.export({ type: 'pkcs1', format: 'pem' }));
        const dnsKey = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
        const resolver = async (name, type) => {
            if (type === 'TXT' && name === 'default._domainkey.anon.li') return [[`v=DKIM1; k=rsa; p=${dnsKey}`]];
            if (type === 'TXT' && name === '_dmarc.anon.li') return [['v=DMARC1; p=quarantine']];
            const err = new Error(`no record for ${name}`);
            err.code = 'ENOTFOUND';
            throw err;
        };

        const previousDir = process.env.LOCAL_DKIM_DIR;
        process.env.LOCAL_DKIM_DIR = keyDir;
        const dkimKeys = require('../../lib/dkim-keys');
        dkimKeys.clearCache();
        try {
            const { queued, run } = setup();
            const raw = [
                'From: Shop <news@shop.example>',
                'To: shop@anon.li',
                'Subject: A long subject line that the sending client decided',
                '\tto fold',
                'MIME-Version: 1.0',
                'Content-Type: multipart/alternative;',
                '\tboundary="b1"',
                '',
                '--b1',
                'Content-Type: text/plain',
                '',
                '.dotted',
                '--b1',
                'Content-Type: text/html',
                '',
                '<p>hi</p>',
                '--b1--',
                '',
            ].join('\r\n');
            const txn = await receivedTransaction(raw, {
                notes: {
                    alias: alias([{ email: 'me@example.net', pgpPublicKey: null }]),
                    mailauth: { spf: { status: { result: 'pass' } }, dmarc: { status: { result: 'pass' }, policy: 'reject' } },
                },
                mailFrom: new Address('news@shop.example'),
            });
            assert.equal((await run(txn)).code, OK);
            const copy = queued[0];

            const hookPlugin = (mod) => Object.assign(Object.create(mod), {
                config: { get: () => ({}) },
                loginfo() {}, logwarn() {},
                logerror: (m) => assert.fail(String(m)),
            });
            await new Promise(resolve => arcSign.seal_message.call(hookPlugin(arcSign), resolve, { transaction: copy }));
            await new Promise(resolve => dkimCustom.sign_message.call(hookPlugin(dkimCustom), resolve, { transaction: copy }));

            const result = await authenticate(await readStored(copy), {
                resolver, ip: '192.0.2.1', helo: 'mx.anon.li', mta: 'mx.example.net', sender: copy.mail_from.address,
            });
            assert.equal(result.dkim.results[0].status.result, 'pass', result.dkim.results[0].status.comment);
            assert.equal(result.dkim.results[0].signingDomain, 'anon.li');
            assert.equal(result.arc.status.result, 'pass', JSON.stringify(result.arc.status));
            assert.equal(result.dmarc.status.result, 'pass', 'munged From aligns with the anon.li signature');
        } finally {
            if (previousDir === undefined) delete process.env.LOCAL_DKIM_DIR;
            else process.env.LOCAL_DKIM_DIR = previousDir;
            dkimKeys.clearCache();
            fs.rmSync(keyDir, { recursive: true, force: true });
        }
    });
});

describe('queue.forward outbound MX routing', () => {
    const dnsPromises = require('node:dns').promises;
    const plugin = { logerror() {}, config: { get: (name) => (name === 'me' ? 'mx.anon.li' : undefined) } };
    const route = (domain, notes = {}) => new Promise(resolve => {
        queueForward.route_mx.call(plugin, (code, mx) => resolve({ code, mx }), { todo: { notes } }, domain);
    });
    const LOOPBACK = [{ priority: 10, exchange: '127.0.0.1', port: 25 }];

    it('sends Purelymail relays to Purelymail', async () => {
        const { code, mx } = await route('anon.li', { purelymail_mx: true });
        assert.equal(code, OK);
        assert.deepEqual(mx.map(m => m.exchange), ['mailserver.purelymail.com']);
    });

    it('delivers mail for domains whose MX is this host to our own listener', async (t) => {
        let lookups = 0;
        t.mock.method(dnsPromises, 'resolveMx', async (domain) => {
            lookups++;
            if (domain === 'hosted.example') return [{ exchange: 'MX.anon.li', priority: 10 }];
            if (domain === 'elsewhere.example') return [{ exchange: 'mx.elsewhere.example', priority: 10 }];
            throw Object.assign(new Error('queryMx ENOTFOUND'), { code: 'ENOTFOUND' });
        });

        for (const domain of ['anon.li', 'reply.anon.li']) {
            assert.deepEqual(await route(domain), { code: OK, mx: LOOPBACK }, domain);
        }
        assert.equal(lookups, 0, 'our own domains need no lookup');

        assert.deepEqual(await route('hosted.example'), { code: OK, mx: LOOPBACK });
        await route('hosted.example');
        assert.equal(lookups, 1, 'results are cached');

        assert.equal((await route('elsewhere.example')).code, undefined, 'verified elsewhere: normal delivery');
        assert.equal((await route('nomx.example')).code, undefined, 'lookup failures: normal delivery');
    });
});
