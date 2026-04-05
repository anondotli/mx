'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const pgpMime = require('../../lib/pgp-mime');

describe('pgp-mime extractMimeEntity', () => {
    it('splits simple text/plain message', () => {
        const raw = Buffer.from(
            'From: a@b.com\r\n' +
            'To: c@d.com\r\n' +
            'Subject: Test\r\n' +
            'Content-Type: text/plain; charset=utf-8\r\n' +
            '\r\n' +
            'Hello world\r\n'
        );

        const { transportHeaders, mimeEntity } = pgpMime.extractMimeEntity(raw);

        assert.ok(transportHeaders.includes('From: a@b.com'));
        assert.ok(transportHeaders.includes('To: c@d.com'));
        assert.ok(transportHeaders.includes('Subject: Test'));
        assert.ok(!transportHeaders.includes('Content-Type'));

        const entity = mimeEntity.toString('utf-8');
        assert.ok(entity.includes('Content-Type: text/plain'));
        assert.ok(entity.includes('Hello world'));
    });

    it('handles multipart message with Content-Transfer-Encoding', () => {
        const raw = Buffer.from(
            'From: a@b.com\r\n' +
            'Subject: Multi\r\n' +
            'Content-Type: multipart/mixed; boundary="abc"\r\n' +
            'Content-Transfer-Encoding: 7bit\r\n' +
            'MIME-Version: 1.0\r\n' +
            '\r\n' +
            '--abc\r\n' +
            'Content-Type: text/plain\r\n' +
            '\r\n' +
            'body\r\n' +
            '--abc--\r\n'
        );

        const { transportHeaders, mimeEntity } = pgpMime.extractMimeEntity(raw);

        assert.ok(!transportHeaders.includes('Content-Type'));
        assert.ok(!transportHeaders.includes('MIME-Version'));
        assert.ok(transportHeaders.includes('From: a@b.com'));

        const entity = mimeEntity.toString('utf-8');
        assert.ok(entity.includes('Content-Type: multipart/mixed'));
        assert.ok(entity.includes('--abc'));
    });

    it('preserves X- headers as transport headers', () => {
        const raw = Buffer.from(
            'From: a@b.com\r\n' +
            'X-Anon-Forward: true\r\n' +
            'Content-Type: text/plain\r\n' +
            '\r\n' +
            'body\r\n'
        );

        const { transportHeaders } = pgpMime.extractMimeEntity(raw);
        assert.ok(transportHeaders.includes('X-Anon-Forward: true'));
    });

    it('handles folded (continuation) headers', () => {
        const raw = Buffer.from(
            'From: a@b.com\r\n' +
            'Subject: A very long\r\n' +
            ' subject line\r\n' +
            'Content-Type: text/plain\r\n' +
            '\r\n' +
            'body\r\n'
        );

        const { transportHeaders } = pgpMime.extractMimeEntity(raw);
        assert.ok(transportHeaders.includes('Subject: A very long\r\n subject line'));
    });

    it('throws on missing header/body separator', () => {
        assert.throws(
            () => pgpMime.extractMimeEntity(Buffer.from('no separator here')),
            /Could not find end of headers/
        );
    });
});

describe('pgp-mime buildPgpMimeMessage', () => {
    const fakeArmor = '-----BEGIN PGP MESSAGE-----\r\nbase64data\r\n-----END PGP MESSAGE-----';

    it('produces valid multipart/encrypted Content-Type', () => {
        const msg = pgpMime.buildPgpMimeMessage('From: a@b.com\r\nSubject: Test', fakeArmor);

        assert.ok(msg.includes('Content-Type: multipart/encrypted'));
        assert.ok(msg.includes('protocol="application/pgp-encrypted"'));
        assert.ok(msg.includes('MIME-Version: 1.0'));
    });

    it('includes PGP version identification part', () => {
        const msg = pgpMime.buildPgpMimeMessage('From: a@b.com', fakeArmor);

        assert.ok(msg.includes('Content-Type: application/pgp-encrypted'));
        assert.ok(msg.includes('Version: 1'));
    });

    it('includes encrypted armor in second part', () => {
        const msg = pgpMime.buildPgpMimeMessage('From: a@b.com', fakeArmor);

        assert.ok(msg.includes('Content-Type: application/octet-stream'));
        assert.ok(msg.includes(fakeArmor));
    });

    it('preserves transport headers', () => {
        const headers = 'From: a@b.com\r\nTo: c@d.com\r\nSubject: Hello';
        const msg = pgpMime.buildPgpMimeMessage(headers, fakeArmor);

        assert.ok(msg.startsWith('From: a@b.com'));
        assert.ok(msg.includes('To: c@d.com'));
        assert.ok(msg.includes('Subject: Hello'));
    });

    it('uses unique boundary that does not appear in armor', () => {
        const msg = pgpMime.buildPgpMimeMessage('From: a@b.com', fakeArmor);

        const match = msg.match(/boundary="([^"]+)"/);
        assert.ok(match, 'boundary found in Content-Type');
        assert.ok(!fakeArmor.includes(match[1]), 'boundary does not collide with armor');
    });
});
