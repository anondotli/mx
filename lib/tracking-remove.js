'use strict';

const { Iconv } = require('iconv');
const { writeRawMessage, readRawMessage } = require('./raw-message');

// Tracking removal for forwarded copies.
//
// This runs on the outgoing copy at queue time rather than as a DATA-phase body
// filter on the inbound transaction: a body filter rewrites the stored message
// before the mailauth plugin verifies it, and Haraka re-encodes every text
// part of a filtered message (QP re-wrapped, base64 re-chunked), so inbound
// DKIM failed with "body hash did not verify" on nearly all mail — wrongly
// failing DMARC and the "SPF fail + no DKIM pass" rejection in data.spam_check.

const TRACKING_DOMAINS = [
    'mailtrack.io', 'yesware.com', 'pixel.facebook.com',
    'googleadservices.com', 'doubleclick.net'
];
const TRACKING_PARAMS = new Set([
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id',
    'fbclid', 'gclid', 'dclid', 'msclkid', 'mc_cid', 'mc_eid',
]);

// Query separators as they appear inside an HTML attribute: a bare '&' or one
// of its character references (&amp; &#38; &#x26;). Captured so the rebuilt
// query keeps the original encoding.
const QUERY_SEPARATOR_RE = /(&(?:amp;|#0*38;|#x0*26;)?)/i;

function clean_html(html) {
    html = stripTrackingImages(html);
    html = cleanLinks(html);
    return html;
}

function stripTrackingImages(html) {
    return html.replace(/<img\b[^>]*>/gi, tag => {
        const src = getAttributeValue(tag, 'src');
        const width = getAttributeValue(tag, 'width');
        const height = getAttributeValue(tag, 'height');
        const style = getAttributeValue(tag, 'style');

        if (src && isTrackingDomain(hostnameOf(src))) return '';

        if ((isOnePixel(width) && isOnePixel(height)) || isOnePixelStyle(style)) {
            return '';
        }

        return tag;
    });
}

function cleanLinks(html) {
    return html.replace(
        /(\shref\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/gi,
        (match, prefix, doubleQuoted, singleQuoted, bare) => {
            const url = doubleQuoted ?? singleQuoted ?? bare;
            if (!/^https?:\/\//i.test(url)) return match;

            const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : '';
            if (isTrackingDomain(hostnameOf(url))) {
                return `${prefix}${quote || '"'}#${quote || '"'}`;
            }

            const cleaned = stripTrackingParams(url);
            if (cleaned === url) return match;
            return `${prefix}${quote}${cleaned}${quote}`;
        }
    );
}

// Removes tracking parameters from a URL as written in HTML, leaving every other
// byte untouched: re-serialising through URL/URLSearchParams would re-encode the
// whole query (breaking signed links) and misreads "&amp;" as part of a key.
function stripTrackingParams(url) {
    const hashIdx = url.indexOf('#');
    const beforeHash = hashIdx === -1 ? url : url.slice(0, hashIdx);
    const fragment = hashIdx === -1 ? '' : url.slice(hashIdx);
    const queryIdx = beforeHash.indexOf('?');
    if (queryIdx === -1) return url;

    const tokens = beforeHash.slice(queryIdx + 1).split(QUERY_SEPARATOR_RE);
    const kept = [];
    for (let i = 0; i < tokens.length; i += 2) {
        if (isTrackingParam(tokens[i])) continue;
        kept.push(kept.length === 0 ? tokens[i] : tokens[i - 1] + tokens[i]);
    }
    if (kept.length * 2 - 1 === tokens.length) return url;

    const query = kept.join('');
    return `${beforeHash.slice(0, queryIdx)}${query ? `?${query}` : ''}${fragment}`;
}

function isTrackingParam(pair) {
    const rawKey = pair.split('=')[0];
    let key = rawKey;
    try {
        key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
    } catch (_err) {
        // Keep the raw key on malformed percent-encoding.
    }
    return TRACKING_PARAMS.has(key.toLowerCase());
}

function hostnameOf(url) {
    try {
        return new URL(url.replace(/&amp;/gi, '&')).hostname;
    } catch (_err) {
        return ''; // Malformed or relative URL.
    }
}

function getAttributeValue(tag, name) {
    const match = tag.match(new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, 'i'));
    return match ? (match[1] ?? match[2] ?? match[3] ?? '') : '';
}

function isTrackingDomain(hostname) {
    const host = String(hostname || '').toLowerCase();
    return TRACKING_DOMAINS.some(domain => host === domain || host.endsWith(`.${domain}`));
}

function isOnePixel(value) {
    return /^[01](?:px)?$/i.test(String(value || '').trim());
}

function isOnePixelStyle(style) {
    if (!style) return false;
    const normalized = String(style).toLowerCase().replace(/\s+/g, '');
    return /(?:^|;)width:[01](?:px)?(?:;|$)/.test(normalized) &&
        /(?:^|;)height:[01](?:px)?(?:;|$)/.test(normalized);
}

function normalizeCharset(enc) {
    if (!enc || typeof enc !== 'string') return 'utf-8';
    return enc.replace(/^broken\/\//i, '') || 'utf-8';
}

function iconvFor(from, to) {
    try {
        return new Iconv(from, to);
    } catch (_err) {
        return null; // Charset unknown to iconv.
    }
}

// Cleans one decoded text/html part. Returns the re-encoded bytes, or null when
// nothing changed or the charset cannot be round-tripped safely.
function cleanHtmlPart(buf, enc) {
    if (typeof enc === 'string' && /^broken\/\//i.test(enc)) return null;
    const charset = normalizeCharset(enc);

    // //TRANSLIT//IGNORE avoids hard failures on stray bytes so we never abort
    // forwarding over charset edge cases.
    const decoder = iconvFor(charset, 'UTF-8//TRANSLIT//IGNORE');
    const encoder = iconvFor('UTF-8', `${charset}//TRANSLIT//IGNORE`);
    if (!decoder || !encoder) return null;

    try {
        const html = decoder.convert(buf).toString('utf8');
        const cleaned = clean_html(html);
        if (cleaned === html) return null;
        return encoder.convert(Buffer.from(cleaned, 'utf8'));
    } catch (_err) {
        return null; // e.g. a truncated multibyte sequence: leave the part alone
    }
}

// Runs clean_html over every inline text/html part of a raw message, using
// Haraka's MIME parser to decode/re-encode transfer encodings and charsets.
// Messages without trackers come back as the original buffer, byte for byte.
// Whether "text/html" (any case) occurs in the message, without copying it.
function mentionsTextHtml(buf) {
    const needle = 'text/html';
    for (let slash = buf.indexOf(0x2f, 4); slash !== -1 && slash + 4 < buf.length; slash = buf.indexOf(0x2f, slash + 1)) {
        let match = true;
        for (let k = 0; k < needle.length && match; k++) {
            const byte = buf[slash - 4 + k];
            match = k === 4 ? byte === 0x2f : (byte | 0x20) === needle.charCodeAt(k);
        }
        if (match) return true;
    }
    return false;
}

async function removeTracking(raw, createTransaction) {
    // No HTML part, nothing to clean: skip the second MIME pass
    if (!mentionsTextHtml(raw)) return { raw, changed: false };

    const txn = createTransaction();
    let changed = false;
    txn.add_body_filter('text/html', (_ct, enc, buf) => {
        const cleaned = cleanHtmlPart(buf, enc);
        if (!cleaned) return buf;
        changed = true;
        return cleaned;
    });

    try {
        await writeRawMessage(txn, raw);
        if (!changed) return { raw, changed: false };
        return { raw: await readRawMessage(txn), changed: true };
    } finally {
        txn.message_stream.destroy(); // drops the spool file of a large message
    }
}

module.exports = { clean_html, stripTrackingParams, cleanHtmlPart, removeTracking };
