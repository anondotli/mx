'use strict';

const crypto = require('crypto');

// Headers that describe the message envelope/transport (kept in the outer message)
const TRANSPORT_HEADERS = new Set([
    'from', 'to', 'cc', 'bcc', 'subject', 'date', 'message-id',
    'reply-to', 'in-reply-to', 'references', 'return-path',
    'received', 'dkim-signature', 'arc-seal', 'arc-message-signature',
    'arc-authentication-results', 'authentication-results',
    'x-anon-forward', 'x-pgp-encryption-failed',
]);

/**
 * Split a raw RFC 5322 message into transport headers (outer) and
 * the MIME entity (Content-Type + body, to be encrypted).
 *
 * @param {Buffer} rawMessage  Full message (headers + \r\n\r\n + body)
 * @returns {{ transportHeaders: string, mimeEntity: Buffer }}
 */
exports.extractMimeEntity = function (rawMessage) {
    const eoh = rawMessage.indexOf('\r\n\r\n');
    if (eoh === -1) throw new Error('Could not find end of headers');

    const headerBlock = rawMessage.slice(0, eoh).toString('utf-8');
    const body = rawMessage.slice(eoh + 4);               // after \r\n\r\n

    const transportLines = [];
    const contentLines = [];

    // Parse headers respecting folded (continuation) lines
    const lines = headerBlock.split('\r\n');
    let current = null;
    let currentIsTransport = false;

    for (const line of lines) {
        if (/^[ \t]/.test(line)) {
            // Continuation of previous header
            if (current !== null) {
                current += '\r\n' + line;
            }
            continue;
        }
        // Flush previous header
        if (current !== null) {
            (currentIsTransport ? transportLines : contentLines).push(current);
        }
        // Start new header
        current = line;
        const colonIdx = line.indexOf(':');
        const name = colonIdx > 0 ? line.slice(0, colonIdx).trim().toLowerCase() : '';
        currentIsTransport = TRANSPORT_HEADERS.has(name) || name.startsWith('x-');
    }
    // Flush last header
    if (current !== null) {
        (currentIsTransport ? transportLines : contentLines).push(current);
    }

    // The MIME entity = content headers + \r\n\r\n + body
    const contentHeader = contentLines.length > 0
        ? contentLines.join('\r\n') + '\r\n'
        : '';
    const mimeEntity = Buffer.concat([
        Buffer.from(contentHeader + '\r\n'),
        body,
    ]);

    return {
        transportHeaders: transportLines.join('\r\n'),
        mimeEntity,
    };
};

/**
 * Build a PGP/MIME message (RFC 3156 §4) from transport headers
 * and an ASCII-armored PGP encrypted block.
 *
 * @param {string} transportHeaders  Original transport headers (From, To, Subject…)
 * @param {string} encryptedArmor    ASCII-armored PGP message
 * @returns {string} Complete RFC 5322 message ready for delivery
 */
exports.buildPgpMimeMessage = function (transportHeaders, encryptedArmor) {
    const boundary = `pgpmime-${crypto.randomUUID()}`;

    const headers = [
        transportHeaders,
        `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${boundary}"`,
        'MIME-Version: 1.0',
    ].join('\r\n');

    const body = [
        `--${boundary}`,
        'Content-Type: application/pgp-encrypted',
        'Content-Description: PGP/MIME version identification',
        '',
        'Version: 1',
        '',
        `--${boundary}`,
        'Content-Type: application/octet-stream; name="encrypted.asc"',
        'Content-Description: OpenPGP encrypted message',
        'Content-Disposition: inline; filename="encrypted.asc"',
        '',
        encryptedArmor,
        '',
        `--${boundary}--`,
        '',
    ].join('\r\n');

    return headers + '\r\n\r\n' + body;
};
