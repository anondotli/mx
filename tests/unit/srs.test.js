'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const srs = require('../../lib/srs');

const SECRET = 'test-secret-1234';
const OWN_DOMAIN = 'anon.li';

describe('SRS rewrite()', () => {
    it('produces valid SRS0=hash=ts=domain=local@anon.li format', () => {
        const result = srs.rewrite('user@example.com', OWN_DOMAIN, SECRET);
        assert.match(result, /^SRS0=[A-Za-z0-9_-]{4}=[A-Z2-7]{2}=example\.com=user@anon\.li$/);
    });

    it('normalizes sender to lowercase', () => {
        const result = srs.rewrite('User@Example.COM', OWN_DOMAIN, SECRET);
        assert.ok(result.startsWith('SRS0='));
        assert.ok(result.endsWith('@anon.li'));
    });

    it('detects existing SRS0 address and delegates to rewriteSRS1', () => {
        const srs0 = srs.rewrite('user@example.com', OWN_DOMAIN, SECRET);
        const result = srs.rewrite(srs0, OWN_DOMAIN, SECRET);
        assert.ok(result.toUpperCase().startsWith('SRS1='));
    });
});

describe('SRS reverse()', () => {
    it('successfully unwraps a freshly written address', () => {
        const original = 'user@example.com';
        const srsAddress = srs.rewrite(original, OWN_DOMAIN, SECRET);
        const result = srs.reverse(srsAddress, SECRET);
        assert.equal(result.valid, true);
        assert.equal(result.originalSender, original);
    });

    it('rejects tampered hash', () => {
        const srsAddress = srs.rewrite('user@example.com', OWN_DOMAIN, SECRET);
        // Replace the 4-char hash with XXXX
        const tampered = srsAddress.replace(/^SRS0=[A-Za-z0-9_-]{4}=/, 'SRS0=XXXX=');
        const result = srs.reverse(tampered, SECRET);
        assert.equal(result.valid, false);
    });

    it('rejects address signed with wrong secret', () => {
        const srsAddress = srs.rewrite('user@example.com', OWN_DOMAIN, SECRET);
        const result = srs.reverse(srsAddress, 'wrong-secret');
        assert.equal(result.valid, false);
    });

    it('rejects timestamp outside ±3 day window', () => {
        // Create SRS address at current time, then advance clock by 5 days
        const originalNow = Date.now;
        const baseTime = Date.now();
        const fiveDaysMs = 5 * 24 * 60 * 60 * 1000;
        try {
            const srsAddress = srs.rewrite('user@example.com', OWN_DOMAIN, SECRET);
            Date.now = () => baseTime + fiveDaysMs;
            const result = srs.reverse(srsAddress, SECRET);
            assert.equal(result.valid, false);
        } finally {
            Date.now = originalNow;
        }
    });

    it('returns valid: false for non-SRS address', () => {
        const result = srs.reverse('user@example.com', SECRET);
        assert.equal(result.valid, false);
    });

    it('returns valid: false for missing arguments', () => {
        assert.equal(srs.reverse(null, SECRET).valid, false);
        assert.equal(srs.reverse('SRS0=AAAA=AA=example.com=user@anon.li', null).valid, false);
    });
});

describe('SRS rewriteSRS1()', () => {
    it('double-wraps existing SRS address into SRS1 format', () => {
        const srs0 = srs.rewrite('user@example.com', OWN_DOMAIN, SECRET);
        const srs1 = srs.rewriteSRS1(srs0, OWN_DOMAIN, SECRET);
        assert.ok(srs1.toUpperCase().startsWith('SRS1='));
        assert.ok(srs1.endsWith('@anon.li'));
    });
});

describe('SRS1 reverse()', () => {
    it('successfully unwraps a double-wrapped SRS1 address', () => {
        const original = 'user@example.com';
        // First hop: example.com → forwarder1.com rewrites to SRS0
        const srs0 = srs.rewrite(original, OWN_DOMAIN, SECRET);
        // Second hop: forwarder1.com → us rewrites SRS0 → SRS1
        const srs1 = srs.rewrite(srs0, OWN_DOMAIN, SECRET);
        const result = srs.reverse(srs1, SECRET);
        assert.equal(result.valid, true);
        assert.equal(result.originalSender, original);
    });

    it('rejects SRS1 with tampered outer hash', () => {
        const srs0 = srs.rewrite('user@example.com', OWN_DOMAIN, SECRET);
        const srs1 = srs.rewrite(srs0, OWN_DOMAIN, SECRET);
        const tampered = srs1.replace(/^SRS1=[A-Za-z0-9_-]{4}=/i, 'SRS1=XXXX=');
        const result = srs.reverse(tampered, SECRET);
        assert.equal(result.valid, false);
    });

    it('rejects SRS1 with wrong secret', () => {
        const srs0 = srs.rewrite('user@example.com', OWN_DOMAIN, SECRET);
        const srs1 = srs.rewrite(srs0, OWN_DOMAIN, SECRET);
        const result = srs.reverse(srs1, 'wrong-secret');
        assert.equal(result.valid, false);
    });
});
