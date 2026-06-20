'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const queueForward = require('../../plugins/queue.forward');

async function readStream(stream) {
    const chunks = [];

    for await (const chunk of stream) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }

    return Buffer.concat(chunks);
}

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
            mail_from: { address: () => 'smtp@example.org' },
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
            mail_from: { address: () => 'smtp@example.org' },
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
            mail_from: { address: () => 'smtp@example.org' },
        };

        assert.equal(queueForward.getOriginalSenderAddress(txn), 'smtp@example.org');
    });

    it('wraps buffer contents as a readable stream for outbound.send_email', async () => {
        const original = Buffer.from('Subject: test\r\n\r\nbody\r\n');
        const prepared = queueForward.prepareOutboundContents(original);

        assert.equal(typeof prepared.on, 'function');
        assert.deepEqual(await readStream(prepared), original);
    });

    it('leaves string contents unchanged', () => {
        const original = 'Subject: test\r\n\r\nbody\r\n';
        const prepared = queueForward.prepareOutboundContents(original);

        assert.equal(prepared, original);
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

        const updated = queueForward.replaceReplyToHeader(original, 'token123@reply.anon.li');
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

        assert.equal(queueForward.replaceReplyToHeader(original), original);
    });

    it('replaces a folded From header without orphaning its continuation lines', () => {
        const original = Buffer.from(
            'From: A Very Long\r\n' +
            '\tDisplay Name <real@dropbox.com>\r\n' +
            'Subject: hi\r\n' +
            '\r\n' +
            'body\r\n'
        );

        const updated = queueForward.replaceFromHeader(original, '"Dropbox via anon.li" <me@anon.li>');
        const head = updated.subarray(0, updated.indexOf('\r\n\r\n')).toString('utf8');

        assert.match(head, /From: "Dropbox via anon\.li" <me@anon\.li>/);
        assert.doesNotMatch(head, /real@dropbox\.com|Display Name/);
        assert.match(head, /Subject: hi/);
    });

    it('returns the original raw message when no replacement From is provided', () => {
        const original = Buffer.from('From: sender@example.com\r\n\r\nbody\r\n');
        assert.equal(queueForward.replaceFromHeader(original), original);
    });
});

describe('queue.forward envelope sender', () => {
    const { Address } = require('address-rfc2821');
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
    });
});

describe('queue.forward From munging', () => {
    const txnWith = (policy, fromHeader) => ({
        notes: { mailauth: { dmarc: { policy } } },
        header: { get: name => (name === 'From' ? fromHeader : null) },
    });

    it('munges only when the sender publishes reject or quarantine', () => {
        assert.equal(queueForward.shouldMungeFrom(txnWith('reject')), true);
        assert.equal(queueForward.shouldMungeFrom(txnWith('quarantine')), true);
        assert.equal(queueForward.shouldMungeFrom(txnWith('none')), false);
        assert.equal(queueForward.shouldMungeFrom({ notes: {} }), false);
        assert.equal(queueForward.shouldMungeFrom({}), false);
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
