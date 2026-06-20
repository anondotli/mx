'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const bounceToken = require('../../lib/bounce-token');

beforeEach(() => {
    bounceToken._clearLocalStore();
});

describe('bounce-token', () => {
    it('roundtrips create() → decode()', async () => {
        const token = await bounceToken.create('bounces+abc=anon.li@em6623.email.openai.com');
        const decoded = await bounceToken.decode(token);

        assert.ok(decoded);
        assert.equal(decoded.originalSender, 'bounces+abc=anon.li@em6623.email.openai.com');
    });

    it('keeps the full BNC= address within the RFC-5321 64-octet limit', async () => {
        const longSender =
            'bounces+108370056-3140-6hvyb0xbfo=anon.li@em6623.email.openai.com';
        const token = await bounceToken.create(longSender);
        const localPart = `${bounceToken.ADDRESS_PREFIX}${token}`;
        assert.ok(
            Buffer.byteLength(localPart, 'utf8') <= 64,
            `local-part is ${localPart.length} octets`,
        );

        // The parser that rejected the over-length SRS address must accept this.
        const { Address } = require('address-rfc2821');
        assert.doesNotThrow(() => new Address(`${localPart}@anon.li`));
    });

    it('returns null for unknown tokens', async () => {
        assert.equal(await bounceToken.decode('this-token-was-never-issued'), null);
    });

    it('returns null for malformed input', async () => {
        assert.equal(await bounceToken.decode(''), null);
        assert.equal(await bounceToken.decode('has spaces'), null);
        assert.equal(await bounceToken.decode('has@at'), null);
    });

    it('issues unique tokens per call', async () => {
        const a = await bounceToken.create('a@b.com');
        const b = await bounceToken.create('a@b.com');
        assert.notEqual(a, b);
    });
});
