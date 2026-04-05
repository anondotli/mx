'use strict';

const { Iconv } = require('iconv');

const TRACKING_DOMAINS = [
    'mailtrack.io', 'yesware.com', 'pixel.facebook.com',
    'googleadservices.com', 'doubleclick.net'
];
const TRACKING_PARAMS = ['utm_source', 'utm_medium', 'fbclid', 'gclid', 'mc_cid'];

exports.register = function () {
    this.register_hook('data', 'enable_body_parsing');
    this.register_hook('data_post', 'process_body');
};

exports.enable_body_parsing = function (next, connection) {
    const txn = connection.transaction;
    if (!txn) return next();

    // Skip tracking removal for relay — preserves original DKIM signatures
    if (txn.notes.zoho_relay) return next();

    txn.parse_body = true;
    txn.add_body_filter('text/html', (_ct, enc, buf) => {
        const charset = normalizeCharset(enc);
        if (!canRewriteCharset(enc, charset)) return buf;

        const html = decodeHtml(buf, charset);
        const cleaned = this.clean_html(html);

        if (cleaned === html) return buf;

        const encoded = encodeHtml(cleaned, charset);
        if (!encoded) return buf;

        txn.notes.tracking_removed = true;
        return encoded;
    });

    next();
};

exports.process_body = function (next, connection) {
    const txn = connection.transaction;
    if (txn?.notes?.tracking_removed) {
        txn.add_header('X-Privacy', 'Tracking-Removed');
    }
    next();
};

exports.clean_html = function (html) {
    html = stripTrackingImages(html);
    html = cleanLinks(html);
    return html;
};

function stripTrackingImages(html) {
    return html.replace(/<img\b[^>]*>/gi, tag => {
        const src = getAttributeValue(tag, 'src');
        const width = getAttributeValue(tag, 'width');
        const height = getAttributeValue(tag, 'height');
        const style = getAttributeValue(tag, 'style');

        if (src) {
            try {
                const parsed = new URL(src);
                if (isTrackingDomain(parsed.hostname)) return '';
            } catch (_err) {
                // Ignore malformed or relative src values.
            }
        }

        if ((isOnePixel(width) && isOnePixel(height)) || isOnePixelStyle(style)) {
            return '';
        }

        return tag;
    });
}

function cleanLinks(html) {
    return html.replace(/href\s*=\s*(?:(["'])([^"']*)\1|([^\s>]+))/gi, (match, quote, quotedUrl, bareUrl) => {
        const url = quotedUrl ?? bareUrl;
        if (!/^https?:\/\//i.test(url)) return match;

        try {
            const parsed = new URL(url);
            if (isTrackingDomain(parsed.hostname)) {
                return `href=${quote || '"'}#${quote || '"'}`;
            }

            let changed = false;
            TRACKING_PARAMS.forEach(param => {
                if (parsed.searchParams.has(param)) {
                    parsed.searchParams.delete(param);
                    changed = true;
                }
            });

            if (!changed) return match;

            const wrapper = quote || '"';
            return `href=${wrapper}${parsed.toString()}${wrapper}`;
        } catch (_err) {
            return match;
        }
    });
}

function decodeHtml(buf, charset) {
    // charset → UTF-8 string. //TRANSLIT//IGNORE avoids hard failures on
    // stray bytes so we never abort forwarding over charset edge cases.
    const conv = new Iconv(charset, 'UTF-8//TRANSLIT//IGNORE');
    return conv.convert(buf).toString('utf8');
}

function encodeHtml(html, charset) {
    try {
        const conv = new Iconv('UTF-8', `${charset}//TRANSLIT//IGNORE`);
        return conv.convert(Buffer.from(html, 'utf8'));
    } catch (_err) {
        return null;
    }
}

function normalizeCharset(enc) {
    if (!enc || typeof enc !== 'string') return 'utf-8';
    return enc.replace(/^broken\/\//i, '') || 'utf-8';
}

function canRewriteCharset(rawCharset, normalizedCharset) {
    if (typeof rawCharset === 'string' && /^broken\/\//i.test(rawCharset)) return false;
    // iconv has no encodingExists helper — probe by attempting construction.
    try {
        // eslint-disable-next-line no-new
        new Iconv(normalizedCharset, 'UTF-8//TRANSLIT//IGNORE');
        return true;
    } catch (_err) {
        return false;
    }
}

function getAttributeValue(tag, name) {
    const match = tag.match(new RegExp(`${name}\\s*=\\s*(?:(["'])(.*?)\\1|([^\\s>]+))`, 'i'));
    return match ? (match[2] ?? match[3] ?? '') : '';
}

function isTrackingDomain(hostname) {
    const host = String(hostname || '').toLowerCase();
    return TRACKING_DOMAINS.some(domain => host === domain || host.endsWith(`.${domain}`));
}

function isOnePixel(value) {
    return /^(?:1|1px)$/i.test(String(value || '').trim());
}

function isOnePixelStyle(style) {
    if (!style) return false;
    const normalized = String(style).toLowerCase().replace(/\s+/g, '');
    return /(?:^|;)width:1(?:px)?(?:;|$)/.test(normalized) &&
        /(?:^|;)height:1(?:px)?(?:;|$)/.test(normalized);
}
