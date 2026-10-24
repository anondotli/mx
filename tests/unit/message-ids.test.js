'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const messageIds = require('../../lib/message-ids');

describe('message-ids', () => {
    beforeEach(() => {
        process.env.MAIL_API_SECRET = 'secret';
        messageIds._clearLocalStore();
    });

    it('derives a stable public ID that does not reveal the client ID', () => {
        const a = messageIds.publicId('<x@laptop.example>');
        assert.equal(a, messageIds.publicId('<x@laptop.example>'));
        assert.match(a, /^<[A-Za-z0-9_-]{32}@anon\.li>$/);
        assert.doesNotMatch(a, /laptop/);
    });

    it('extracts the first <id> of a header value', () => {
        assert.equal(messageIds.firstId(' <a@b>\n'), '<a@b>');
        assert.equal(messageIds.firstId(''), null);
    });

    it('rewrites only IDs of replies sent through us, keeping folding and order', async () => {
        await messageIds.remember('<mine@laptop.example>', 'shop@anon.li');
        const value = '<theirs@shop.example>\n\t<mine@laptop.example> <other@x.example>';
        const pub = messageIds.publicId('<mine@laptop.example>');
        assert.deepEqual(
            await messageIds.toPublic([value, '<mine@laptop.example>']),
            [`<theirs@shop.example>\n\t${pub} <other@x.example>`, pub]
        );
    });

    it('maps public IDs back to the client IDs and leaves unknown ones alone', async () => {
        await messageIds.remember('<mine@laptop.example>', 'Shop@anon.li');
        const pub = messageIds.publicId('<mine@laptop.example>');
        const unknown = messageIds.publicId('<never@sent.example>');
        assert.deepEqual(
            await messageIds.toClient([`<theirs@shop.example> ${pub} ${unknown}`, pub], 'shop@anon.li'),
            [`<theirs@shop.example> <mine@laptop.example> ${unknown}`, '<mine@laptop.example>']
        );
    });

    it('never reveals a client ID on mail to any other alias', async () => {
        await messageIds.remember('<mine@laptop.example>', 'shop@anon.li');
        const pub = messageIds.publicId('<mine@laptop.example>');
        assert.deepEqual(await messageIds.toClient([pub], 'someone-else@anon.li'), [pub]);
    });

    it('returns values without IDs unchanged', async () => {
        assert.deepEqual(await messageIds.toPublic(['no ids here']), ['no ids here']);
        assert.deepEqual(await messageIds.toClient(['no ids here'], 'shop@anon.li'), ['no ids here']);
    });
});
