'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const queueForward = require('../../plugins/queue.forward');

async function readStream(stream) {
    const chunks = [];

    for await (const chunk of stream) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }

    return Buffer.concat(chunks);
}

describe('queue.forward helpers', () => {
    it('wraps buffer contents as a readable stream for outbound.send_email', async () => {
        const original = Buffer.from('Subject: test\r\n\r\nbody\r\n');
        const prepared = queueForward.prepareOutboundContents(original);

        assert.equal(typeof prepared.on, 'function');
        assert.deepEqual(await readStream(prepared), original);
    });

    it('leaves string contents unchanged', () => {
        const original = 'Subject: test\r\n\r\nbody\r\n';
        const prepared = queueForward.prepareOutboundContents(original);

        assert.equal(prepared, original);
    });

    it('replaces Reply-To while preserving folded headers and raw body bytes', () => {
        const body = Buffer.from([0x00, 0xff, 0x61, 0x62, 0x63, 0x0d, 0x0a]);
        const original = Buffer.concat([
            Buffer.from(
                'From: sender@example.com\r\n' +
                'Reply-To: old@example.com\r\n' +
                '\tOld Name\r\n' +
                'Subject: test\r\n' +
                '\r\n'
            ),
            body,
        ]);

        const updated = queueForward.replaceReplyToHeader(original, 'token123@reply.anon.li');
        const marker = updated.indexOf('\r\n\r\n');

        assert.notEqual(marker, -1);
        assert.match(updated.subarray(0, marker).toString('utf8'), /Reply-To: token123@reply\.anon\.li/);
        assert.doesNotMatch(updated.subarray(0, marker).toString('utf8'), /old@example\.com|Old Name/);
        assert.deepEqual(updated.subarray(marker + 4), body);
    });

    it('returns the original raw message when no replacement Reply-To is provided', () => {
        const original = Buffer.from(
            'From: sender@example.com\r\n' +
            'Reply-To: old@example.com\r\n' +
            '\r\n' +
            'body\r\n'
        );

        assert.equal(queueForward.replaceReplyToHeader(original), original);
    });
});
