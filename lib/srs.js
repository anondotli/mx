'use strict';

const crypto = require('crypto');

const SRS_SEPARATOR = '=';
const TIMESTAMP_DIVISOR = 86400;
const TIMESTAMP_MODULO = 1024;
const HASH_LENGTH = 4;
const MAX_AGE_DAYS = 3;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function encodeBase32(num) {
    if (num === 0) return BASE32_ALPHABET[0];
    let result = '';
    while (num > 0) {
        result = BASE32_ALPHABET[num % 32] + result;
        num = Math.floor(num / 32);
    }
    // FIX: Pad with 'A' (index 0), not '0'
    return result.padStart(2, BASE32_ALPHABET[0]);
}

function decodeBase32(str) {
    let result = 0;
    for (const char of str.toUpperCase()) {
        const index = BASE32_ALPHABET.indexOf(char);
        if (index === -1) return null;
        result = result * 32 + index;
    }
    return result;
}

function getTimestamp() {
    const days = Math.floor(Date.now() / 1000 / TIMESTAMP_DIVISOR);
    return encodeBase32(days % TIMESTAMP_MODULO);
}

function generateHash(timestamp, domain, localPart, secret) {
    const data = `${timestamp}${SRS_SEPARATOR}${domain}${SRS_SEPARATOR}${localPart}`;
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(data.toLowerCase());
    return hmac.digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .substring(0, HASH_LENGTH);
}

// Some MTAs lowercase the local part of the address they bounce to, which
// would break a case-sensitive comparison of the base64 hash. Like postsrsd
// and libsrs2, accept a case-insensitive match (constant-time).
function hashMatches(hash, expected) {
    const a = Buffer.from(String(hash).toLowerCase());
    const b = Buffer.from(expected.toLowerCase());
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function timestampIsFresh(timestamp) {
    const decodedDay = decodeBase32(timestamp);
    if (decodedDay === null) return false;
    const currentDays = Math.floor(Date.now() / 1000 / TIMESTAMP_DIVISOR) % TIMESTAMP_MODULO;
    const diff = Math.abs(decodedDay - currentDays);
    return Math.min(diff, TIMESTAMP_MODULO - diff) <= MAX_AGE_DAYS;
}

exports.rewrite = function(sender, ownDomain, secret) {
    if (typeof sender !== 'string' || !sender.trim()) throw new Error('Invalid sender');
    sender = sender.trim();
    const senderLower = sender.toLowerCase();
    if (senderLower.startsWith('srs0=') || senderLower.startsWith('srs1=')) {
        // Preserve case of inner SRS address (hash is case-sensitive)
        return exports.rewriteSRS1(sender, ownDomain, secret);
    }
    sender = senderLower;
    
    const atIndex = sender.lastIndexOf('@');
    if (atIndex < 1) throw new Error('Invalid sender');
    
    const localPart = sender.substring(0, atIndex);
    const domain = sender.substring(atIndex + 1);
    const timestamp = getTimestamp();
    const hash = generateHash(timestamp, domain, localPart, secret);
    
    return `SRS0${SRS_SEPARATOR}${hash}${SRS_SEPARATOR}${timestamp}${SRS_SEPARATOR}${domain}${SRS_SEPARATOR}${localPart}@${ownDomain}`;
};

exports.rewriteSRS1 = function(srsAddress, ownDomain, secret) {
    const atIndex = srsAddress.lastIndexOf('@');
    const localPart = srsAddress.substring(0, atIndex);
    const originalDomain = srsAddress.substring(atIndex + 1);
    const timestamp = getTimestamp();
    const hash = generateHash(timestamp, originalDomain, localPart, secret);
    
    return `SRS1${SRS_SEPARATOR}${hash}${SRS_SEPARATOR}${timestamp}${SRS_SEPARATOR}${originalDomain}${SRS_SEPARATOR}${localPart}@${ownDomain}`;
};

exports.reverse = function(srsAddress, secret) {
    if (!srsAddress || !secret) return { valid: false };

    // Strip @domain suffix if present
    const atIndex = srsAddress.indexOf('@');
    const localPart = atIndex >= 0 ? srsAddress.substring(0, atIndex) : srsAddress;

    const upperLocal = localPart.toUpperCase();

    // Handle SRS1 (double-wrapped): SRS1=hash=timestamp=forwarderDomain=SRS0...
    if (upperLocal.startsWith('SRS1' + SRS_SEPARATOR)) {
        const parts = localPart.split(SRS_SEPARATOR);
        // Minimum: ['SRS1', hash, timestamp, forwarderDomain, 'SRS0', ...]
        if (parts.length < 6) return { valid: false };

        const hash = parts[1];
        const timestamp = parts[2];
        const forwarderDomain = parts[3];

        // Verify SRS1 HMAC (covers forwarder domain + inner SRS local part)
        const innerLocalPart = parts.slice(4).join(SRS_SEPARATOR);
        const expectedHash = generateHash(timestamp, forwarderDomain, innerLocalPart, secret);
        if (!hashMatches(hash, expectedHash)) return { valid: false };
        if (!timestampIsFresh(timestamp)) return { valid: false };

        // The inner address was minted by the previous forwarder. If that was
        // us, unwrap it all the way; otherwise the bounce belongs to that
        // forwarder, which alone can verify its own hash (SRS spec §4.2).
        const innerAddress = `${innerLocalPart}@${forwarderDomain}`;
        const inner = exports.reverse(innerAddress, secret);
        if (inner.valid) return inner;
        return { valid: true, originalSender: innerAddress };
    }

    // Handle SRS0 bounces
    if (!upperLocal.startsWith('SRS0' + SRS_SEPARATOR)) return { valid: false };

    // Split: SRS0=hash=timestamp=domain=localPart (SRS_SEPARATOR is '=')
    const parts = localPart.split(SRS_SEPARATOR);
    // Minimum: ['SRS0', hash, timestamp, domain, localPart]
    if (parts.length < 5) return { valid: false };

    const hash = parts[1];
    const timestamp = parts[2];
    const domain = parts[3];
    const originalLocalPart = parts.slice(4).join(SRS_SEPARATOR);

    // Verify HMAC and that the timestamp is within ±3 days (handles modulo wrapping)
    const expectedHash = generateHash(timestamp, domain, originalLocalPart, secret);
    if (!hashMatches(hash, expectedHash)) return { valid: false };
    if (!timestampIsFresh(timestamp)) return { valid: false };

    return {
        valid: true,
        originalSender: `${originalLocalPart}@${domain}`,
    };
};
