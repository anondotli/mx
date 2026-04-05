'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// We need to re-require to get a fresh module for circuit breaker tests,
// but since Node caches modules, we test the exported functions directly.
const {
    constantTimeCompare,
    validateEmailFormat,
    validateDomainFormat,
    validateDomainList,
    retryCall,
} = require('../../lib/security');

describe('constantTimeCompare()', () => {
    it('returns true for identical strings', () => {
        assert.ok(constantTimeCompare('secret123', 'secret123'));
    });

    it('returns false for different strings', () => {
        assert.ok(!constantTimeCompare('secret123', 'secret456'));
    });

    it('returns false for different lengths', () => {
        assert.ok(!constantTimeCompare('short', 'longer-string'));
    });

    it('returns false when a is null', () => {
        assert.ok(!constantTimeCompare(null, 'value'));
    });

    it('returns false when b is null', () => {
        assert.ok(!constantTimeCompare('value', null));
    });

    it('returns false when both are empty', () => {
        assert.ok(!constantTimeCompare('', ''));
    });
});

describe('validateEmailFormat()', () => {
    it('accepts valid email', () => {
        assert.ok(validateEmailFormat('user@example.com'));
    });

    it('rejects email without @', () => {
        assert.ok(!validateEmailFormat('userexample.com'));
    });

    it('rejects null', () => {
        assert.ok(!validateEmailFormat(null));
    });

    it('rejects email longer than 320 chars', () => {
        const long = 'a'.repeat(310) + '@example.com';
        assert.ok(!validateEmailFormat(long));
    });
});

describe('validateDomainFormat()', () => {
    it('accepts valid domain', () => {
        assert.ok(validateDomainFormat('example.com'));
    });

    it('rejects domain starting with dash', () => {
        assert.ok(!validateDomainFormat('-example.com'));
    });

    it('rejects domain with double dots', () => {
        assert.ok(!validateDomainFormat('example..com'));
    });

    it('rejects null', () => {
        assert.ok(!validateDomainFormat(null));
    });
});

describe('validateDomainList()', () => {
    it('filters valid domains from list', () => {
        const result = validateDomainList(['example.com', '-bad', 'good.org']);
        assert.deepStrictEqual(result, ['example.com', 'good.org']);
    });

    it('returns default for non-array', () => {
        assert.deepStrictEqual(validateDomainList(null), ['anon.li']);
    });
});

describe('retryCall()', () => {
    it('returns result on first success', async () => {
        const result = await retryCall(async () => 'ok', 1, 1000);
        assert.equal(result, 'ok');
    });

    it('retries on failure then succeeds', async () => {
        let calls = 0;
        const result = await retryCall(async () => {
            calls++;
            if (calls < 2) throw new Error('fail');
            return 'ok';
        }, 3, 1000);
        assert.equal(result, 'ok');
        assert.equal(calls, 2);
    });

    it('throws after exhausting retries', async () => {
        await assert.rejects(
            retryCall(async () => { throw new Error('always fail'); }, 1, 1000),
            { message: 'always fail' }
        );
    });
});
