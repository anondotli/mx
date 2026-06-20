'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const replyToken = require('../../lib/reply-token');

beforeEach(() => {
    replyToken._clearLocalStore();
});

describe('reply-token', () => {
    it('roundtrips create() → decode()', async () => {
        const token = await replyToken.create('alice@external.com', 'tag@anon.li', 'bob@personal.example');
        const decoded = await replyToken.decode(token);

        assert.ok(decoded);
        assert.equal(decoded.originalSender, 'alice@external.com');
        assert.equal(decoded.aliasEmail, 'tag@anon.li');
        assert.equal(decoded.recipientEmail, 'bob@personal.example');
    });

    it('produces a local-part within the RFC-5321 64-octet limit', async () => {
        const token = await replyToken.create(
            'a-very-long-sender-address@some-external-domain.example',
            'my-alias@anon.li',
            'my-personal-mailbox@my-own-domain.example',
        );
        assert.ok(Buffer.byteLength(token, 'utf8') <= 64, `token is ${token.length} octets`);

        // And the parser that rejected the old design must accept it now.
        const { Address } = require('address-rfc2821');
        assert.doesNotThrow(() => new Address(`<${token}@reply.anon.li>`));
    });

    it('returns null for unknown tokens', async () => {
        assert.equal(await replyToken.decode('this-token-was-never-issued'), null);
    });

    it('returns null for malformed input', async () => {
        assert.equal(await replyToken.decode(''), null);
        assert.equal(await replyToken.decode('has spaces'), null);
        assert.equal(await replyToken.decode('has@at'), null);
    });

    it('issues unique tokens per call', async () => {
        const a = await replyToken.create('a@b.com', 'c@d.com', 'e@f.com');
        const b = await replyToken.create('a@b.com', 'c@d.com', 'e@f.com');
        assert.notEqual(a, b);
    });
});
