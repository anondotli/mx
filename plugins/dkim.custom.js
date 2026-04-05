'use strict';

const { fetch } = require('undici');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { retryCall } = require('../lib/security');

// Simple in-memory cache for DKIM keys (TTL: 1 hour)
const keyCache = new Map();
const KEY_CACHE_TTL = 3600000;

// RFC 6376 §3.4.1 — relaxed header canonicalization
function canonicalizeHeaderRelaxed(name, value) {
    return name.toLowerCase() + ':' +
        value
            .replace(/\r\n[ \t]+/g, ' ')  // unfold continuation lines
            .replace(/[ \t]+/g, ' ')       // collapse WSP runs
            .trimEnd();                    // strip trailing whitespace
}

// RFC 6376 §3.4.3 — simple body canonicalization (operates on raw bytes)
function canonicalizeBodySimple(body) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);

    // Normalize bare LF to CRLF (replace \n not preceded by \r)
    const chunks = [];
    for (let i = 0; i < buf.length; i++) {
        if (buf[i] === 0x0A && (i === 0 || buf[i - 1] !== 0x0D)) {
            chunks.push(Buffer.from([0x0D, 0x0A]));
        } else {
            chunks.push(buf.subarray(i, i + 1));
        }
    }
    let normalized = Buffer.concat(chunks);

    // Strip trailing empty lines (sequences of \r\n at the end)
    let end = normalized.length;
    while (end >= 2 && normalized[end - 2] === 0x0D && normalized[end - 1] === 0x0A) {
        end -= 2;
    }
    normalized = normalized.subarray(0, end);

    // Ensure single final CRLF
    return Buffer.concat([normalized, Buffer.from([0x0D, 0x0A])]);
}

exports.register = function () {
    this.register_hook('pre_send_trans_email', 'sign_message');
};

exports.sign_message = async function (next, connection) {
    const plugin = this;
    const txn = connection.transaction;
    if (!txn) return next();

    try {
        // Determine domain — prefer reply alias domain over SRS-rewritten envelope
        let domain = 'anon.li';
        if (txn.notes.reply_dkim_domain) {
            domain = txn.notes.reply_dkim_domain;
        } else if (txn.mail_from.host && txn.mail_from.host !== 'anon.li') {
            domain = txn.mail_from.host;
        }

        // Fetch Key
        let keyData = await this.get_key(domain);
        if (!keyData) {
            // Fallback to anon.li for SRS rewritten mails
            if (domain !== 'anon.li') keyData = await this.get_key('anon.li');
            if (!keyData) return next();
        }

        // Headers to sign (RFC 6376 §3.5 recommended set)
        const headersToSign = ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Content-Type', 'MIME-Version'];
        // Only include headers that are present in the message
        const signedHeaders = headersToSign.filter(h => txn.header.get(h));

        // RFC 6376 §3.4.1 — build canonicalized header signing input
        let headerData = '';
        signedHeaders.forEach(h => {
            headerData += canonicalizeHeaderRelaxed(h, txn.header.get(h)) + '\r\n';
        });

        // Get body from message_stream as raw Buffer (txn.body may be null if parse_body is off)
        const rawBody = await new Promise((resolve) => {
            txn.message_stream.get_data((buf) => {
                const raw = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
                const sep = raw.indexOf('\r\n\r\n');
                resolve(sep === -1 ? Buffer.alloc(0) : raw.subarray(sep + 4));
            });
        });

        // RFC 6376 §3.4.3 — canonicalize body and compute body hash
        const canonBody = canonicalizeBodySimple(rawBody);
        const bodyHash = crypto.createHash('sha256').update(canonBody).digest('base64');

        // RFC 6376 §3.7 — build DKIM-Signature with empty b=, then append its
        // relaxed canonicalization to the signing input (no trailing CRLF)
        const dkimUnsigned = `v=1; a=rsa-sha256; c=relaxed/simple; d=${domain}; s=${keyData.selector}; t=${Math.floor(Date.now() / 1000)}; h=${signedHeaders.join(':')}; bh=${bodyHash}; b=`;
        const signingInput = headerData + canonicalizeHeaderRelaxed('dkim-signature', dkimUnsigned);

        const sign = crypto.createSign('RSA-SHA256');
        sign.update(signingInput);

        const privateKey = crypto.createPrivateKey({
            key: keyData.privateKey,
            format: 'pem',
        });

        const signature = sign.sign(privateKey, 'base64');
        txn.add_leading_header('DKIM-Signature', dkimUnsigned + signature);

        next();
    } catch (err) {
        plugin.logerror(`DKIM Error: ${err.message}`);
        next(); // Don't fail mail on signing error
    }
};

exports.get_key = async function(domain) {
    const cached = keyCache.get(domain);
    if (cached && cached.expires > Date.now()) return cached.data;

    // Try local key files first (config/dkim/<domain>/private)
    try {
        const keyPath = path.resolve(__dirname, '..', 'config', 'dkim', domain, 'private');
        const privateKey = fs.readFileSync(keyPath, 'utf8');
        const cfg = this.config.get('dkim_sign.ini');
        const selector = cfg[`domain ${domain}`]?.selector || 'default';
        const data = { privateKey, selector };
        keyCache.set(domain, { data, expires: Date.now() + KEY_CACHE_TTL });
        return data;
    } catch (_e) {
        // No local key, try API
    }

    try {
        const data = await retryCall(async (signal) => {
            const res = await fetch(
                `${process.env.FRONTEND_URL}/api/internal/dkim?domain=${encodeURIComponent(domain)}`,
                {
                    headers: { 'x-api-secret': process.env.MAIL_API_SECRET },
                    signal,
                }
            );
            if (res.status === 404) return null;
            if (!res.ok) throw new Error(`DKIM API ${res.status}`);
            return res.json();
        }, { breakerKey: 'dkim' });

        if (data) keyCache.set(domain, { data, expires: Date.now() + KEY_CACHE_TTL });
        return data;
    } catch (_err) {
        // Log but don't throw — caller handles null
        return null;
    }
};

// Exported for testing
exports.canonicalizeHeaderRelaxed = canonicalizeHeaderRelaxed;
exports.canonicalizeBodySimple = canonicalizeBodySimple;
