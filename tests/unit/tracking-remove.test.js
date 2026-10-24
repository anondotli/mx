'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { Iconv } = require('iconv');
const { createTransaction } = require('../helpers/haraka');
const tracking = require('../../lib/tracking-remove');

const encodeCharset = (str, charset) =>
    new Iconv('UTF-8', `${charset}//TRANSLIT//IGNORE`).convert(Buffer.from(str, 'utf8'));
const decodeCharset = (buf, charset) =>
    new Iconv(charset, 'UTF-8//TRANSLIT//IGNORE').convert(buf).toString('utf8');

describe('tracking-remove clean_html', () => {
    it('leaves ordinary HTML unchanged', () => {
        const html = '<html><body><p>Hello <b>world</b></p><img src="https://example.com/logo.png" width="600" height="200"></body></html>';
        assert.equal(tracking.clean_html(html), html);
    });

    it('removes known tracking query params from links', () => {
        const html = '<a href="https://example.com/news?utm_source=mail&fbclid=123&id=42">Read more</a>';
        assert.equal(
            tracking.clean_html(html),
            '<a href="https://example.com/news?id=42">Read more</a>'
        );
    });

    it('removes the whole utm_* family', () => {
        const html = '<a href="https://example.com/?utm_campaign=x&utm_term=y&utm_content=z&p=1">x</a>';
        assert.equal(tracking.clean_html(html), '<a href="https://example.com/?p=1">x</a>');
    });

    it('keeps HTML-escaped separators and the remaining parameters intact', () => {
        // Regression: URLSearchParams read "amp;id" as a key and rebuilt the
        // link as ?amp%3Bid=123, losing the id parameter.
        const html = '<a href="https://shop.example/item?utm_source=news&amp;id=123&amp;utm_medium=email">Buy</a>';
        assert.equal(tracking.clean_html(html), '<a href="https://shop.example/item?id=123">Buy</a>');
    });

    it('does not re-encode the parameters it keeps (signed links stay valid)', () => {
        const html = '<a href="https://example.com/v?sig=a%2Fb+c&e=x,y&utm_source=n#frag">v</a>';
        assert.equal(tracking.clean_html(html), '<a href="https://example.com/v?sig=a%2Fb+c&e=x,y#frag">v</a>');
    });

    it('drops the "?" when only tracking parameters were present', () => {
        const html = "<a href='https://example.com/p?utm_source=a&amp;gclid=b'>p</a>";
        assert.equal(tracking.clean_html(html), "<a href='https://example.com/p'>p</a>");
    });

    it('handles double-quoted URLs that contain an apostrophe', () => {
        const html = '<a href="https://example.com/it\'s?utm_source=a&id=1">x</a>';
        assert.equal(tracking.clean_html(html), '<a href="https://example.com/it\'s?id=1">x</a>');
    });

    it('ignores data-href and similar attributes', () => {
        const html = '<a data-href="https://example.com/?utm_source=a" href="https://example.com/">x</a>';
        assert.equal(tracking.clean_html(html), html);
    });

    it('replaces known tracking-domain links with inert targets', () => {
        const html = '<a href="https://mailtrack.io/trace/abc">Open</a>';
        assert.equal(tracking.clean_html(html), '<a href="#">Open</a>');
    });

    it('removes 1x1 and 0x0 tracking pixels without rewriting the rest of the HTML', () => {
        assert.equal(
            tracking.clean_html('<div>Hello<img src="https://example.com/pixel.gif" width="1" height="1"></div>'),
            '<div>Hello</div>'
        );
        assert.equal(
            tracking.clean_html('<div>Hi<img src="https://example.com/o.gif" width="0" height="0"></div>'),
            '<div>Hi</div>'
        );
    });

    it('decides on the src attribute, not data-src', () => {
        const html = '<img data-src="https://pixel.facebook.com/x.gif" src="https://example.com/logo.png" width="120" height="40">';
        assert.equal(tracking.clean_html(html), html);
    });

    it('removes images loaded from known tracking domains', () => {
        const html = '<div><img src="https://pixel.facebook.com/open.gif" width="600" height="200"></div>';
        assert.equal(tracking.clean_html(html), '<div></div>');
    });

    // Regression: a Tuta user reported Discord IP-verification mail arriving with "a
    // major missing part." Tracking removal must never strip the actionable content —
    // Discord's verify button (a plain discord.com link, not a tracking domain) and its
    // logo (non-1px, non-tracking) must pass through byte-for-byte.
    it('leaves a Discord-style verification email untouched', () => {
        const html =
            '<html><body>' +
            '<h1>New login location detected</h1>' +
            '<p>We noticed a login to your account from a new IP address.</p>' +
            '<a href="https://discord.com/verify?token=abc123" ' +
            'style="background:#5865F2;color:#fff;padding:12px 24px;">Authorize Login</a>' +
            '<img src="https://cdn.discordapp.com/assets/logo.png" width="120" height="40">' +
            '</body></html>';
        assert.equal(tracking.clean_html(html), html);
    });
});

describe('tracking-remove cleanHtmlPart', () => {
    it('rewrites HTML using the source charset', () => {
        const original = encodeCharset('<a href="https://example.com/news?utm_source=mail&id=42">Za njo č</a>', 'windows-1250');
        const filtered = tracking.cleanHtmlPart(original, 'windows-1250');
        assert.equal(
            decodeCharset(filtered, 'windows-1250'),
            '<a href="https://example.com/news?id=42">Za njo č</a>'
        );
    });

    it('returns null when nothing changed', () => {
        assert.equal(tracking.cleanHtmlPart(Buffer.from('<p>hi</p>'), 'utf-8'), null);
    });

    it('returns null instead of throwing on a truncated multibyte sequence', () => {
        const truncated = Buffer.concat([
            Buffer.from('<a href="https://example.com/?utm_source=a">x</a>'),
            Buffer.from([0xe2, 0x82]),
        ]);
        assert.equal(tracking.cleanHtmlPart(truncated, 'utf-8'), null);
    });

    it('returns null for unsupported or broken charsets so the original bytes stay intact', () => {
        const original = Buffer.from('<a href="https://example.com/news?utm_source=mail&id=42">Read more</a>');
        assert.equal(tracking.cleanHtmlPart(original, 'broken//x-mac-cyrillic'), null);
        assert.equal(tracking.cleanHtmlPart(original, 'x-no-such-charset'), null);
    });
});

describe('tracking-remove removeTracking (Haraka MIME parser)', () => {
    const boundary = 'b=_alt_1';
    const multipart = (html, htmlCte = 'quoted-printable') => Buffer.from(
        'From: News <news@example.com>\r\n' +
        'To: alias@anon.li\r\n' +
        'Subject: Weekly\r\n' +
        'MIME-Version: 1.0\r\n' +
        `Content-Type: multipart/alternative; boundary="${boundary}"\r\n` +
        '\r\n' +
        `--${boundary}\r\n` +
        'Content-Type: text/plain; charset=utf-8\r\n' +
        'Content-Transfer-Encoding: quoted-printable\r\n' +
        '\r\n' +
        'Plain text body with a long line that was wrapped by the sender at its ow=\r\n' +
        'n width.\r\n' +
        '.a line that starts with a dot\r\n' +
        '\r\n' +
        `--${boundary}\r\n` +
        'Content-Type: text/html; charset=utf-8\r\n' +
        `Content-Transfer-Encoding: ${htmlCte}\r\n` +
        '\r\n' +
        html +
        `\r\n--${boundary}--\r\n`
    );

    it('returns the original buffer untouched when there is nothing to remove', async () => {
        const raw = multipart('<p>No trackers here.</p>');
        const result = await tracking.removeTracking(raw, createTransaction);
        assert.equal(result.changed, false);
        assert.equal(result.raw, raw);
    });

    it('removes a tracker while keeping both alternatives and every other byte of meaning', async () => {
        const raw = multipart(
            '<p>Hello</p><a href=3D"https://discord.com/verify?token=3Dabc&amp;utm_source=3Dx">Verify</a>' +
            '<img src=3D"https://t.example/p.gif" width=3D"1" height=3D"1">'
        );
        const result = await tracking.removeTracking(raw, createTransaction);
        assert.equal(result.changed, true);

        const out = result.raw.toString('utf8');
        assert.match(out, /Content-Type: text\/plain/);
        assert.match(out, /Content-Type: text\/html/);
        assert.match(out, new RegExp(`--${boundary}--`));
        assert.match(out, /^\.a line that starts with a dot$/m, 'leading dot kept, not doubled');
        assert.match(out, /discord\.com\/verify\?token=3Dabc"/);
        assert.doesNotMatch(out, /utm_source|p\.gif/);
    });

    it('cleans base64-encoded HTML parts', async () => {
        const html = '<a href="https://example.com/?id=1&utm_medium=mail">x</a>';
        const raw = multipart(Buffer.from(html).toString('base64'), 'base64');
        const result = await tracking.removeTracking(raw, createTransaction);
        assert.equal(result.changed, true);
        const encoded = result.raw.toString('utf8').split(`--${boundary}`)[2].split('\r\n\r\n')[1];
        assert.equal(Buffer.from(encoded, 'base64').toString('utf8'), '<a href="https://example.com/?id=1">x</a>');
    });

    it('detects an HTML part in any case and position', async () => {
        for (const ct of ['text/html', 'TEXT/HTML', 'Text/Html']) {
            const raw = Buffer.from(`Content-Type: ${ct}\r\n\r\n<img src="https://x.example/p.gif" width="1" height="1">\r\n`);
            assert.equal((await tracking.removeTracking(raw, createTransaction)).changed, true, ct);
        }
    });

    it('skips messages without an HTML part entirely', async () => {
        const raw = Buffer.from('From: a@example.com\r\nSubject: s\r\n\r\nhttps://x.example/?utm_source=a\r\n');
        let created = 0;
        const result = await tracking.removeTracking(raw, () => { created++; return createTransaction(); });
        assert.equal(result.raw, raw);
        assert.equal(created, 0);
    });

    it('leaves HTML attachments alone', async () => {
        const raw = Buffer.from(
            'From: a@example.com\r\nMIME-Version: 1.0\r\n' +
            'Content-Type: multipart/mixed; boundary="m"\r\n\r\n' +
            '--m\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n' +
            '--m\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename="page.html"\r\n\r\n' +
            '<img src="https://t.example/p.gif" width="1" height="1">\r\n' +
            '--m--\r\n'
        );
        const result = await tracking.removeTracking(raw, createTransaction);
        assert.equal(result.changed, false);
        assert.equal(result.raw, raw);
    });
});
