'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const db = require('../../lib/db');

// Port of the website's lib/field-encryption.ts encryptField()
function encryptField(plaintext, keyHex) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return 'enc:' + Buffer.concat([iv, encrypted, cipher.getAuthTag()]).toString('base64');
}

describe('db.decryptDkimKey', () => {
    const key = crypto.randomBytes(32).toString('hex');
    const pem = '-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n';
    let previous;
    afterEach(() => {
        if (previous === undefined) delete process.env.DKIM_ENCRYPTION_KEY;
        else process.env.DKIM_ENCRYPTION_KEY = previous;
    });
    const withKey = (value) => {
        previous = process.env.DKIM_ENCRYPTION_KEY;
        if (value === undefined) delete process.env.DKIM_ENCRYPTION_KEY;
        else process.env.DKIM_ENCRYPTION_KEY = value;
    };

    it('decrypts keys encrypted by the website', () => {
        withKey(key);
        assert.equal(db._internal.decryptDkimKey(encryptField(pem, key)), pem);
    });

    it('passes legacy plaintext keys through', () => {
        withKey(undefined);
        assert.equal(db._internal.decryptDkimKey(pem), pem);
    });

    it('throws when the key is missing, malformed or wrong', () => {
        const value = encryptField(pem, key);
        withKey(undefined);
        assert.throws(() => db._internal.decryptDkimKey(value), /DKIM_ENCRYPTION_KEY/);
        process.env.DKIM_ENCRYPTION_KEY = 'xyz';
        assert.throws(() => db._internal.decryptDkimKey(value), /DKIM_ENCRYPTION_KEY/);
        process.env.DKIM_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
        assert.throws(() => db._internal.decryptDkimKey(value));
    });
});

describe('db.sslOption', () => {
    it('uses TLS (unverified) for remote hosts and plaintext for loopback, like the website', () => {
        assert.deepEqual(db._internal.sslOption('postgresql://u:p@db.example.com:5432/x'), { rejectUnauthorized: false });
        assert.equal(db._internal.sslOption('postgresql://u:p@localhost:5432/x'), false);
        assert.equal(db._internal.sslOption('postgresql://u:p@127.0.0.1/x'), false);
        assert.equal(db._internal.sslOption('postgresql://u:p@[::1]/x'), false);
    });
});

describe('db.newId', () => {
    it('produces cuid-shaped ids', () => {
        const ids = new Set(Array.from({ length: 1000 }, () => db._internal.newId()));
        assert.equal(ids.size, 1000);
        for (const id of ids) assert.match(id, /^c[a-z0-9]{24}$/);
    });
});
