'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const pgpEncrypt = require('../../lib/pgp-encrypt');

describe('pgp-encrypt smoke test', () => {
    it('exports encryptBody as an async function', () => {
        assert.equal(typeof pgpEncrypt.encryptBody, 'function');
        // Should return a Promise (async function)
        const maybePromise = pgpEncrypt.encryptBody('hello', null).catch(() => {});
        assert.ok(maybePromise && typeof maybePromise.then === 'function');
    });

    it('rejects with "No public key" when key is null', async () => {
        await assert.rejects(
            () => pgpEncrypt.encryptBody('hello world', null),
            /No public key/
        );
    });

    it('rejects with "No public key" when key is undefined', async () => {
        await assert.rejects(
            () => pgpEncrypt.encryptBody('hello world', undefined),
            /No public key/
        );
    });

    it('rejects with "PGP Encryption failed" for invalid armored key', async () => {
        await assert.rejects(
            () => pgpEncrypt.encryptBody('hello world', 'not-a-valid-pgp-key'),
            /PGP Encryption failed/
        );
    });

    it('rejects with "PGP Encryption failed: Key expired" for expired key marker', async () => {
        // A key that parses but reports expiration in the past would be caught by
        // the getPublicKey() expiry check. Here we verify the error wrapping is consistent.
        // (Full expired-key test requires a real PGP key fixture — covered by integration tests)
        await assert.rejects(
            () => pgpEncrypt.encryptBody('hello', 'invalid-expired-key'),
            /PGP Encryption failed/
        );
    });
});

describe('pgp-encrypt encryptMime', () => {
    it('exports encryptMime as an async function', () => {
        assert.equal(typeof pgpEncrypt.encryptMime, 'function');
    });

    it('rejects with "No public key" when key is null', async () => {
        await assert.rejects(
            () => pgpEncrypt.encryptMime(Buffer.from('test'), null),
            /No public key/
        );
    });

    it('rejects with "PGP Encryption failed" for invalid key', async () => {
        await assert.rejects(
            () => pgpEncrypt.encryptMime(Buffer.from('test'), 'not-a-key'),
            /PGP Encryption failed/
        );
    });
});
