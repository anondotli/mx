'use strict';

// Loads config/ through Haraka's own config loader and asserts the *effective*
// settings. Haraka replaces (does not merge) its default files with ours, and
// reads some keys from a different file than one might expect, so a misplaced
// key silently falls back to "unset".

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

process.env.HARAKA = path.join(__dirname, '../..');
const config = require(path.join(__dirname, '../../node_modules/haraka-config'));

const connection = config.get('connection.ini', {
    booleans: ['-main.strict_rfc1869', '+main.smtputf8', '+headers.add_received', '+headers.show_version', '+headers.clean_auth_results'],
});
const smtp = config.get('smtp.ini');

describe('effective Haraka configuration', () => {
    it('limits message size (connection.ini [max] bytes)', () => {
        assert.equal(connection.max.bytes, 26214400);
        assert.equal(connection.max.mime_parts, 1000);
    });

    it('hides the Haraka version', () => {
        assert.equal(connection.headers.show_version, false);
    });

    it('sets every [message] string so replies never read "undefined"', () => {
        assert.deepEqual(connection.message.greeting, ['anon.li Alias is ready'], 'greeting must be an array (greeting[]=)');
        assert.equal(typeof connection.message.helo, 'string');
        assert.equal(typeof connection.message.close, 'string');
    });

    it('keeps the header limits Haraka enforces', () => {
        assert.equal(connection.headers.max_lines, 1000);
        assert.equal(connection.headers.max_received, 100);
    });

    it('listens on port 25 (smtp.ini [main] listen)', () => {
        assert.equal(smtp.main.listen, '[::0]:25');
        assert.equal(connection.main.listen, undefined, 'connection.ini listen is ignored by Haraka');
    });

    it('reads every rate limit from limit.ini', () => {
        assert.deepEqual(config.get('limit.ini').main, {
            rate_limit_window: 60,
            rate_limit_count: 20,
            max_rejected_rcpts: 10,
            alias_rate_limit_window: 300,
            alias_rate_limit_count: 50,
            catch_all_rate_limit_window: 3600,
            catch_all_rate_limit_count: 30,
        });
    });

    it('enables the expected plugins in order', () => {
        const plugins = config.get('plugins', 'list');
        assert.deepEqual(plugins, [
            'tls', 'limit-upstash', 'mailauth',
            'rcpt_to.bounce', 'rcpt_to.anonli', 'rcpt_to.reply',
            'data.loop_detect', 'data.spam_check',
            'arc.sign', 'dkim.custom',
            'queue.forward',
        ]);
    });
});
