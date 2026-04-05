'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const srs = require('../../lib/srs');

const plugin = require('../../plugins/rcpt_to.bounce');

// Haraka constants
const OK = 906;
const DENY = 902;
const DENYSOFT = 903;

globalThis.OK = OK;
globalThis.DENY = DENY;
globalThis.DENYSOFT = DENYSOFT;

const TEST_SECRET = 'test-secret-key-123';

describe('rcpt_to.bounce', () => {
    let originalEnv;

    beforeEach(() => {
        originalEnv = process.env.MAIL_API_SECRET;
        process.env.MAIL_API_SECRET = TEST_SECRET;
    });

    afterEach(() => {
        process.env.MAIL_API_SECRET = originalEnv;
    });

    function mockConnection(rcptAddress) {
        return {
            transaction: {
                notes: {},
            },
        };
    }

    function callPlugin(rcptAddress) {
        const conn = mockConnection();
        const params = [{ address: () => rcptAddress }];
        let result;
        plugin.check_bounce.call(
            { loginfo: () => {}, logerror: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn,
            params
        );
        return { result, conn };
    }

    it('passes non-SRS addresses through to next plugin', () => {
        const { result } = callPlugin('user@example.com');
        assert.equal(result.code, undefined);
    });

    it('accepts valid SRS0 bounce and sets txn.notes.bounce', () => {
        // Create a valid SRS address
        const srsAddr = srs.rewrite('sender@example.com', 'anon.li', TEST_SECRET);
        const { result, conn } = callPlugin(srsAddr);
        assert.equal(result.code, OK);
        assert.equal(conn.transaction.notes.bounce.originalSender, 'sender@example.com');
    });

    it('rejects SRS0 with tampered hash', () => {
        const srsAddr = srs.rewrite('sender@example.com', 'anon.li', TEST_SECRET);
        // Tamper with the hash
        const tampered = srsAddr.replace(/SRS0=....=/, 'SRS0=XXXX=');
        const { result } = callPlugin(tampered);
        assert.equal(result.code, DENY);
    });

    it('rejects SRS0 signed with wrong secret', () => {
        const srsAddr = srs.rewrite('sender@example.com', 'anon.li', 'wrong-secret');
        const { result } = callPlugin(srsAddr);
        assert.equal(result.code, DENY);
    });

    it('returns DENYSOFT when MAIL_API_SECRET is missing', () => {
        delete process.env.MAIL_API_SECRET;
        const srsAddr = srs.rewrite('sender@example.com', 'anon.li', TEST_SECRET);
        const { result } = callPlugin(srsAddr);
        assert.equal(result.code, DENYSOFT);
    });

    it('passes through when no transaction', () => {
        let called = false;
        plugin.check_bounce.call(
            { loginfo: () => {}, logerror: () => {} },
            () => { called = true; },
            { transaction: null },
            [{ address: () => 'test@test.com' }]
        );
        assert.ok(called);
    });
});
