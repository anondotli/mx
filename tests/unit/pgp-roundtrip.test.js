'use strict';

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const openpgp = require('openpgp');
const pgpEncrypt = require('../../lib/pgp-encrypt');
const pgpMime = require('../../lib/pgp-mime');

// Generate a throwaway key pair once for all tests
let publicKeyArmored;
let privateKeyArmored;

before(async () => {
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'ecc',
        curve: 'curve25519',
        userIDs: [{ name: 'Test', email: 'test@example.com' }],
        format: 'armored',
    });
    publicKeyArmored = publicKey;
    privateKeyArmored = privateKey;
});

// ── encryptBody roundtrip ──────────────────────────────────────────────

describe('encryptBody roundtrip', () => {
    it('encrypts text and decrypts back to original', async () => {
        const plaintext = 'Hello, this is a secret message!';

        const armored = await pgpEncrypt.encryptBody(plaintext, publicKeyArmored);

        assert.ok(armored.includes('-----BEGIN PGP MESSAGE-----'));

        const message = await openpgp.readMessage({ armoredMessage: armored });
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey });

        assert.equal(data, plaintext);
    });
});

// ── encryptMime roundtrip ──────────────────────────────────────────────

describe('encryptMime roundtrip', () => {
    it('encrypts binary MIME entity and decrypts back to original', async () => {
        const mimeEntity = Buffer.from(
            'Content-Type: text/plain; charset=utf-8\r\n' +
            '\r\n' +
            'Secret body with special chars: éàü 🔒\r\n'
        );

        const armored = await pgpEncrypt.encryptMime(mimeEntity, publicKeyArmored);

        assert.ok(armored.includes('-----BEGIN PGP MESSAGE-----'));

        const message = await openpgp.readMessage({ armoredMessage: armored });
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey, format: 'binary' });

        assert.deepEqual(Buffer.from(data), mimeEntity);
    });

    it('preserves multipart MIME with attachment through encrypt/decrypt', async () => {
        const boundary = '----boundary123';
        const mimeEntity = Buffer.from(
            `Content-Type: multipart/mixed; boundary="${boundary}"\r\n` +
            '\r\n' +
            `--${boundary}\r\n` +
            'Content-Type: text/plain; charset=utf-8\r\n' +
            '\r\n' +
            'Hello from the email body\r\n' +
            `--${boundary}\r\n` +
            'Content-Type: application/pdf; name="doc.pdf"\r\n' +
            'Content-Transfer-Encoding: base64\r\n' +
            'Content-Disposition: attachment; filename="doc.pdf"\r\n' +
            '\r\n' +
            'JVBERi0xLjQKMSAwIG9iago=\r\n' +
            `--${boundary}--\r\n`
        );

        const armored = await pgpEncrypt.encryptMime(mimeEntity, publicKeyArmored);
        const message = await openpgp.readMessage({ armoredMessage: armored });
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey, format: 'binary' });

        const decrypted = Buffer.from(data);
        assert.deepEqual(decrypted, mimeEntity);

        // Verify structure is intact
        const text = decrypted.toString('utf-8');
        assert.ok(text.includes('multipart/mixed'));
        assert.ok(text.includes('Hello from the email body'));
        assert.ok(text.includes('doc.pdf'));
        assert.ok(text.includes('JVBERi0xLjQKMSAwIG9iago='));
    });
});

// ── Full PGP/MIME pipeline: extract → encrypt → build → decrypt ────────

describe('full PGP/MIME pipeline', () => {
    it('round-trips a simple email through extract → encrypt → build → decrypt', async () => {
        const originalEmail = Buffer.from(
            'From: sender@example.com\r\n' +
            'To: alias@anon.li\r\n' +
            'Subject: Top Secret\r\n' +
            'Date: Fri, 21 Mar 2026 12:00:00 +0000\r\n' +
            'Message-ID: <abc123@example.com>\r\n' +
            'Content-Type: text/plain; charset=utf-8\r\n' +
            'Content-Transfer-Encoding: 7bit\r\n' +
            '\r\n' +
            'This is the secret message body.\r\n'
        );

        // Step 1: Extract MIME entity
        const { transportHeaders, mimeEntity } = pgpMime.extractMimeEntity(originalEmail);

        assert.ok(transportHeaders.includes('From: sender@example.com'));
        assert.ok(transportHeaders.includes('Subject: Top Secret'));
        assert.ok(!transportHeaders.includes('Content-Type'));

        const entityText = mimeEntity.toString('utf-8');
        assert.ok(entityText.includes('Content-Type: text/plain'));
        assert.ok(entityText.includes('This is the secret message body.'));

        // Step 2: Encrypt
        const armored = await pgpEncrypt.encryptMime(mimeEntity, publicKeyArmored);

        // Step 3: Build PGP/MIME message
        const pgpMimeMsg = pgpMime.buildPgpMimeMessage(transportHeaders, armored);

        // Verify outer structure
        assert.ok(pgpMimeMsg.includes('From: sender@example.com'));
        assert.ok(pgpMimeMsg.includes('Subject: Top Secret'));
        assert.ok(pgpMimeMsg.includes('Content-Type: multipart/encrypted'));
        assert.ok(pgpMimeMsg.includes('protocol="application/pgp-encrypted"'));
        assert.ok(pgpMimeMsg.includes('Version: 1'));
        assert.ok(pgpMimeMsg.includes('-----BEGIN PGP MESSAGE-----'));
        // Original Content-Type should NOT appear in outer headers
        assert.ok(!pgpMimeMsg.startsWith('Content-Type: text/plain'));

        // Step 4: Decrypt and verify original content
        const pgpBlock = armored;
        const message = await openpgp.readMessage({ armoredMessage: pgpBlock });
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey, format: 'binary' });

        const decrypted = Buffer.from(data).toString('utf-8');
        assert.ok(decrypted.includes('Content-Type: text/plain; charset=utf-8'));
        assert.ok(decrypted.includes('This is the secret message body.'));
    });

    it('round-trips a multipart email with HTML and attachment', async () => {
        const boundary = '----=_Part_123';
        const originalEmail = Buffer.from(
            'From: sender@example.com\r\n' +
            'To: alias@anon.li\r\n' +
            'Subject: With Attachment\r\n' +
            'Message-ID: <def456@example.com>\r\n' +
            `Content-Type: multipart/mixed; boundary="${boundary}"\r\n` +
            'MIME-Version: 1.0\r\n' +
            '\r\n' +
            `--${boundary}\r\n` +
            'Content-Type: text/html; charset=utf-8\r\n' +
            '\r\n' +
            '<h1>Hello</h1><p>This is <b>HTML</b></p>\r\n' +
            `--${boundary}\r\n` +
            'Content-Type: image/png; name="photo.png"\r\n' +
            'Content-Transfer-Encoding: base64\r\n' +
            'Content-Disposition: attachment; filename="photo.png"\r\n' +
            '\r\n' +
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk\r\n' +
            `--${boundary}--\r\n`
        );

        const { transportHeaders, mimeEntity } = pgpMime.extractMimeEntity(originalEmail);
        const armored = await pgpEncrypt.encryptMime(mimeEntity, publicKeyArmored);
        const pgpMimeMsg = pgpMime.buildPgpMimeMessage(transportHeaders, armored);

        // Outer message should have subject but NOT the multipart boundary
        assert.ok(pgpMimeMsg.includes('Subject: With Attachment'));
        assert.ok(!pgpMimeMsg.includes(boundary));

        // Decrypt
        const message = await openpgp.readMessage({ armoredMessage: armored });
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });
        const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey, format: 'binary' });

        const decrypted = Buffer.from(data).toString('utf-8');

        // Everything preserved
        assert.ok(decrypted.includes(`multipart/mixed; boundary="${boundary}"`));
        assert.ok(decrypted.includes('<h1>Hello</h1>'));
        assert.ok(decrypted.includes('photo.png'));
        assert.ok(decrypted.includes('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk'));
    });

    it('handles email with Reply-To injection into transport headers', async () => {
        const originalEmail = Buffer.from(
            'From: sender@example.com\r\n' +
            'To: alias@anon.li\r\n' +
            'Subject: Reply Test\r\n' +
            'Reply-To: original-reply@example.com\r\n' +
            'Content-Type: text/plain\r\n' +
            '\r\n' +
            'body\r\n'
        );

        const { transportHeaders, mimeEntity } = pgpMime.extractMimeEntity(originalEmail);

        // Simulate what queue.forward does: replace Reply-To
        let headers = transportHeaders.split('\r\n')
            .filter(l => !/^Reply-To:/i.test(l))
            .join('\r\n');
        headers += '\r\nReply-To: token123@reply.anon.li';

        const armored = await pgpEncrypt.encryptMime(mimeEntity, publicKeyArmored);
        const pgpMimeMsg = pgpMime.buildPgpMimeMessage(headers, armored);

        assert.ok(pgpMimeMsg.includes('Reply-To: token123@reply.anon.li'));
        assert.ok(!pgpMimeMsg.includes('original-reply@example.com'));
    });
});
