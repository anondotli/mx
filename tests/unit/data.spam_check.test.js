'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const plugin = require('../../plugins/data.spam_check');

// Haraka constants
const DENY = 902;
globalThis.DENY = DENY;

function mockConnection(mailauth, notes = {}) {
    return {
        transaction: {
            notes: { mailauth, ...notes },
            mail_from: { address: () => 'sender@example.com' },
            header: { get: () => '' },
            add_header: () => {},
        },
    };
}

describe('data.spam_check', () => {
    it('passes email with no auth results', () => {
        const conn = mockConnection(null);
        let result;
        plugin.spam_check.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, undefined);
    });

    it('skips check for reply emails', () => {
        const conn = mockConnection(
            { dmarc: { status: { result: 'fail' }, policy: 'reject' } },
            { is_reply: true }
        );
        let result;
        plugin.spam_check.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, undefined);
    });

    it('rejects DMARC reject policy', () => {
        const conn = mockConnection({
            dmarc: { status: { result: 'fail' }, policy: 'reject' },
        });
        let result;
        plugin.spam_check.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, DENY);
        assert.match(result.msg, /DMARC/i);
    });

    it('flags but delivers DMARC reject mail for alias traffic', () => {
        const addedHeaders = [];
        const conn = mockConnection(
            { dmarc: { status: { result: 'fail' }, policy: 'reject' } },
            { alias: { id: 'alias-123' } }
        );
        conn.transaction.add_header = (name, val) => { addedHeaders.push({ name, val }); };

        let result;
        plugin.spam_check.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, undefined);
        assert.deepEqual(addedHeaders, [
            { name: 'X-Spam-Flag', val: 'YES' },
            { name: 'X-Spam-Reason', val: 'DMARC fail (policy=reject)' },
        ]);
    });

    it('flags but delivers DMARC quarantine', () => {
        const addedHeaders = [];
        const conn = mockConnection({
            dmarc: { status: { result: 'fail' }, policy: 'quarantine' },
        });
        conn.transaction.add_header = (name, val) => { addedHeaders.push({ name, val }); };

        let result;
        plugin.spam_check.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, undefined);
        assert.deepEqual(addedHeaders, [
            { name: 'X-Spam-Flag', val: 'YES' },
            { name: 'X-Spam-Reason', val: 'DMARC fail (policy=quarantine)' },
        ]);
    });

    it('still rejects alias traffic that also fails SPF with no DKIM pass', () => {
        const conn = mockConnection(
            {
                dmarc: { status: { result: 'fail' }, policy: 'reject' },
                spf: { status: { result: 'fail' } },
                dkim: { results: [{ status: { result: 'fail' } }] },
            },
            { alias: { id: 'alias-123' } }
        );

        let result;
        plugin.spam_check.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, DENY);
        assert.match(result.msg, /SPF/i);
    });

    it('rejects SPF fail with no DKIM pass', () => {
        const conn = mockConnection({
            spf: { status: { result: 'fail' } },
            dkim: { results: [{ status: { result: 'fail' } }] },
        });
        let result;
        plugin.spam_check.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, DENY);
    });

    it('allows SPF fail when DKIM passes', () => {
        const conn = mockConnection({
            spf: { status: { result: 'fail' } },
            dkim: { results: [{ status: { result: 'pass' } }] },
        });
        let result;
        plugin.spam_check.call(
            { loginfo: () => {} },
            (code, msg) => { result = { code, msg }; },
            conn
        );
        assert.equal(result.code, undefined);
    });
});
