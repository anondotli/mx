'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const replyToken = require('../../lib/reply-token');

beforeEach(() => {
    process.env.MAIL_API_SECRET = 'test-secret-for-unit-tests-only';
    replyToken._clearKeyCache();
});

describe('reply-token', () => {
    it('roundtrips create() → decode()', () => {
        const token = replyToken.create('alice@external.com', 'tag@anon.li', 'bob@personal.example');
        const decoded = replyToken.decode(token);

        assert.ok(decoded);
        assert.equal(decoded.originalSender, 'alice@external.com');
        assert.equal(decoded.aliasEmail, 'tag@anon.li');
        assert.equal(decoded.recipientEmail, 'bob@personal.example');
        assert.ok(decoded.expiresAt instanceof Date);
        assert.ok(decoded.expiresAt.getTime() > Date.now());
    });

    it('returns null for tampered tokens', () => {
        const token = replyToken.create('a@b.com', 'c@d.com', 'e@f.com');
        const tampered = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA');
        assert.equal(replyToken.decode(tampered), null);
    });

    it('returns null for malformed input', () => {
        assert.equal(replyToken.decode(''), null);
        assert.equal(replyToken.decode('not-base64url'), null);
        assert.equal(replyToken.decode('AAAA'), null);
    });

    it('returns null when secret differs (key derivation mismatch)', () => {
        const token = replyToken.create('a@b.com', 'c@d.com', 'e@f.com');

        process.env.MAIL_API_SECRET = 'different-secret';
        replyToken._clearKeyCache();

        assert.equal(replyToken.decode(token), null);
    });
});
