'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { canonicalizeHeaderRelaxed, canonicalizeBodySimple } = require('../../plugins/dkim.custom');

describe('canonicalizeHeaderRelaxed()', () => {
    it('lowercases the header name', () => {
        const result = canonicalizeHeaderRelaxed('FROM', 'user@example.com');
        assert.ok(result.startsWith('from:'));
    });

    it('collapses multiple whitespace runs to single space', () => {
        const result = canonicalizeHeaderRelaxed('Subject', 'Hello  World');
        assert.equal(result, 'subject:Hello World');
    });

    it('collapses tabs to single space', () => {
        const result = canonicalizeHeaderRelaxed('Subject', 'Hello\t\tWorld');
        assert.equal(result, 'subject:Hello World');
    });

    it('unfolds continuation lines (CRLF + WSP → single space)', () => {
        const result = canonicalizeHeaderRelaxed('Subject', 'Hello\r\n World');
        assert.equal(result, 'subject:Hello World');
    });

    it('strips trailing whitespace', () => {
        const result = canonicalizeHeaderRelaxed('Subject', 'Hello World   ');
        assert.equal(result, 'subject:Hello World');
    });

    it('preserves colon separator without extra space', () => {
        const result = canonicalizeHeaderRelaxed('From', 'user@example.com');
        assert.equal(result, 'from:user@example.com');
    });
});

describe('canonicalizeBodySimple()', () => {
    it('returns a Buffer', () => {
        const result = canonicalizeBodySimple('Hello');
        assert.ok(Buffer.isBuffer(result));
    });

    it('normalizes bare LF to CRLF', () => {
        const result = canonicalizeBodySimple('Hello\nWorld');
        assert.deepEqual(result, Buffer.from('Hello\r\nWorld\r\n'));
    });

    it('does not double-convert existing CRLF', () => {
        const result = canonicalizeBodySimple('Hello\r\nWorld');
        assert.deepEqual(result, Buffer.from('Hello\r\nWorld\r\n'));
    });

    it('strips trailing blank lines', () => {
        const result = canonicalizeBodySimple('Hello\r\n\r\n\r\n');
        assert.deepEqual(result, Buffer.from('Hello\r\n'));
    });

    it('ensures a single final CRLF on body without trailing newline', () => {
        const result = canonicalizeBodySimple('Hello');
        assert.deepEqual(result, Buffer.from('Hello\r\n'));
    });

    it('handles empty body (returns single CRLF)', () => {
        const result = canonicalizeBodySimple('');
        assert.deepEqual(result, Buffer.from('\r\n'));
    });

    it('preserves 8-bit binary content', () => {
        const binary = Buffer.from([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x80, 0xFF]);
        const result = canonicalizeBodySimple(binary);
        // Should preserve the 8-bit bytes and add trailing CRLF
        assert.deepEqual(result, Buffer.concat([binary, Buffer.from('\r\n')]));
    });
});

describe('DKIM sign → verify round-trip', () => {
    it('produces a signature that can be verified with the public key', () => {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

        const headers = {
            From: 'sender@example.com',
            Subject: 'Test Message',
            Date: 'Thu, 1 Jan 2026 00:00:00 +0000',
        };
        const signedHeaderNames = Object.keys(headers);
        const body = 'Hello, World!\r\n';

        // Build header signing input
        let headerData = '';
        signedHeaderNames.forEach(h => {
            headerData += canonicalizeHeaderRelaxed(h, headers[h]) + '\r\n';
        });

        // Body hash
        const canonBody = canonicalizeBodySimple(body);
        const bodyHash = crypto.createHash('sha256').update(canonBody).digest('base64');

        // Build unsigned DKIM-Signature and full signing input
        const dkimUnsigned = `v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=dkim; t=1735689600; h=${signedHeaderNames.join(':')}; bh=${bodyHash}; b=`;
        const signingInput = headerData + canonicalizeHeaderRelaxed('dkim-signature', dkimUnsigned);

        // Sign
        const sign = crypto.createSign('RSA-SHA256');
        sign.update(signingInput);
        const signature = sign.sign(
            crypto.createPrivateKey({ key: privateKeyPem, format: 'pem', type: 'pkcs8' }),
            'base64'
        );

        // Verify with public key
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(signingInput);
        assert.ok(verify.verify(publicKey, signature, 'base64'), 'Signature should verify');
    });

    it('signing input excludes a trailing CRLF on the DKIM-Signature line', () => {
        // RFC 6376 §3.7: the DKIM-Signature header is added to signing input WITHOUT trailing CRLF
        const dkimUnsigned = 'v=1; a=rsa-sha256; b=';
        const signingInput = canonicalizeHeaderRelaxed('dkim-signature', dkimUnsigned);
        assert.ok(!signingInput.endsWith('\r\n'), 'Signing input must not end with CRLF');
        assert.ok(signingInput.startsWith('dkim-signature:'), 'Must start with lowercased name');
    });
});
