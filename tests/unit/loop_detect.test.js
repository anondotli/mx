'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// Load the plugin module directly
const plugin = require('../../plugins/data.loop_detect');

// Haraka constants (normally globals)
const DENY = 902;

function mockConnection(headers = {}) {
    return {
        transaction: {
            uuid: 'test-uuid',
            header: {
                get(name) {
                    return headers[name] || '';
                },
                get_all(name) {
                    return headers[`${name}_all`] || [];
                },
            },
        },
    };
}

// Make DENY available as a global (Haraka sets these)
globalThis.DENY = DENY;

describe('data.loop_detect', () => {
    it('passes normal email through', () => {
        const conn = mockConnection({
            'X-Anon-Forward': '',
            'Received_all': new Array(5).fill('from example.com'),
        });

        let result;
        plugin.check_loops.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, undefined);
    });

    it('rejects email with X-Anon-Forward header', () => {
        const conn = mockConnection({
            'X-Anon-Forward': 'true',
            'Received_all': [],
        });

        let result;
        plugin.check_loops.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, DENY);
        assert.match(result.msg, /loop/i);
    });

    it('rejects email with too many Received headers', () => {
        const conn = mockConnection({
            'X-Anon-Forward': '',
            'Received_all': new Array(30).fill('from example.com'),
        });

        let result;
        plugin.check_loops.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, DENY);
        assert.match(result.msg, /loop|hops/i);
    });

    it('allows exactly 25 Received headers', () => {
        const conn = mockConnection({
            'X-Anon-Forward': '',
            'Received_all': new Array(25).fill('from example.com'),
        });

        let result;
        plugin.check_loops.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, undefined);
    });

    it('returns next() when no transaction', () => {
        let called = false;
        plugin.check_loops.call(
            { loginfo: () => {} },
            () => { called = true; },
            { transaction: null }
        );
        assert.ok(called);
    });
});
