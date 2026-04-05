'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { Iconv } = require('iconv');
const plugin = require('../../plugins/data.tracking_remove');

const encodeCharset = (str, charset) =>
    new Iconv('UTF-8', `${charset}//TRANSLIT//IGNORE`).convert(Buffer.from(str, 'utf8'));
const decodeCharset = (buf, charset) =>
    new Iconv(charset, 'UTF-8//TRANSLIT//IGNORE').convert(buf).toString('utf8');

describe('data.tracking_remove clean_html', () => {
    it('leaves ordinary HTML unchanged so DKIM can survive forwarding', () => {
        const html = '<html><body><p>Hello <b>world</b></p><img src="https://example.com/logo.png" width="600" height="200"></body></html>';
        assert.equal(plugin.clean_html(html), html);
    });

    it('removes known tracking query params from links', () => {
        const html = '<a href="https://example.com/news?utm_source=mail&fbclid=123&id=42">Read more</a>';
        assert.equal(
            plugin.clean_html(html),
            '<a href="https://example.com/news?id=42">Read more</a>'
        );
    });

    it('replaces known tracking-domain links with inert targets', () => {
        const html = '<a href="https://mailtrack.io/trace/abc">Open</a>';
        assert.equal(plugin.clean_html(html), '<a href="#">Open</a>');
    });

    it('removes 1x1 tracking pixels without rewriting the rest of the HTML', () => {
        const html = '<div>Hello<img src="https://example.com/pixel.gif" width="1" height="1"></div>';
        assert.equal(plugin.clean_html(html), '<div>Hello</div>');
    });

    it('removes images loaded from known tracking domains', () => {
        const html = '<div><img src="https://pixel.facebook.com/open.gif" width="600" height="200"></div>';
        assert.equal(plugin.clean_html(html), '<div></div>');
    });
});

describe('data.tracking_remove hooks', () => {
    it('registers an HTML body filter that flags modified messages', () => {
        let registeredType;
        let filterFn;
        let nextCalled = false;

        const connection = {
            transaction: {
                parse_body: false,
                notes: {},
                add_body_filter(type, fn) {
                    registeredType = type;
                    filterFn = fn;
                },
            },
        };

        plugin.enable_body_parsing.call(plugin, () => {
            nextCalled = true;
        }, connection);

        assert.equal(nextCalled, true);
        assert.equal(connection.transaction.parse_body, true);
        assert.equal(registeredType, 'text/html');
        assert.equal(typeof filterFn, 'function');

        const original = Buffer.from('<a href="https://example.com/news?utm_source=mail&id=42">Read more</a>');
        const filtered = filterFn('text/html', 'utf-8', original);

        assert.equal(filtered.toString('utf8'), '<a href="https://example.com/news?id=42">Read more</a>');
        assert.equal(connection.transaction.notes.tracking_removed, true);
    });

    it('keeps unchanged HTML untouched and does not set the tracking flag', () => {
        let filterFn;

        const connection = {
            transaction: {
                parse_body: false,
                notes: {},
                add_body_filter(_type, fn) {
                    filterFn = fn;
                },
            },
        };

        plugin.enable_body_parsing.call(plugin, () => {}, connection);

        const original = Buffer.from('<p>Hello world</p>');
        const filtered = filterFn('text/html', 'utf-8', original);

        assert.equal(filtered, original);
        assert.equal(connection.transaction.notes.tracking_removed, undefined);
    });

    it('rewrites supported legacy charsets without changing the charset encoding', () => {
        let filterFn;

        const connection = {
            transaction: {
                parse_body: false,
                notes: {},
                add_body_filter(_type, fn) {
                    filterFn = fn;
                },
            },
        };

        plugin.enable_body_parsing.call(plugin, () => {}, connection);

        const originalHtml = '<a href="https://example.com/news?utm_source=mail&id=42">Za njo</a>';
        const original = encodeCharset(originalHtml, 'windows-1250');
        const filtered = filterFn('text/html', 'windows-1250', original);

        assert.equal(
            decodeCharset(filtered, 'windows-1250'),
            '<a href="https://example.com/news?id=42">Za njo</a>'
        );
        assert.equal(connection.transaction.notes.tracking_removed, true);
    });

    it('skips rewriting unsupported charsets so the original bytes stay intact', () => {
        let filterFn;

        const connection = {
            transaction: {
                parse_body: false,
                notes: {},
                add_body_filter(_type, fn) {
                    filterFn = fn;
                },
            },
        };

        plugin.enable_body_parsing.call(plugin, () => {}, connection);

        const original = Buffer.from('<a href="https://example.com/news?utm_source=mail&id=42">Read more</a>');
        const filtered = filterFn('text/html', 'broken//x-mac-cyrillic', original);

        assert.equal(filtered, original);
        assert.equal(connection.transaction.notes.tracking_removed, undefined);
    });

    it('adds the privacy header only when tracking content was removed', () => {
        const addedHeaders = [];

        plugin.process_body(() => {}, {
            transaction: {
                notes: { tracking_removed: true },
                add_header(name, value) {
                    addedHeaders.push([name, value]);
                },
            },
        });

        assert.deepEqual(addedHeaders, [['X-Privacy', 'Tracking-Removed']]);
    });
});
