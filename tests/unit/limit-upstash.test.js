'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { DENYSOFT, DENYSOFTDISCONNECT } = require('../helpers/haraka');
const plugin = require('../../plugins/limit-upstash');

describe('limit-upstash clientBucket', () => {
    it('keeps IPv4 addresses (also IPv4-mapped ones) as they are', () => {
        assert.equal(plugin.clientBucket('192.0.2.7'), '192.0.2.7');
        assert.equal(plugin.clientBucket('::ffff:192.0.2.7'), '192.0.2.7');
    });

    it('buckets IPv6 addresses by /64, whatever their notation', () => {
        const bucket = '2001:db8:1:2::/64';
        assert.equal(plugin.clientBucket('2001:db8:1:2::1'), bucket);
        assert.equal(plugin.clientBucket('2001:db8:1:2:ffff:ffff:ffff:ffff'), bucket);
        assert.equal(plugin.clientBucket('2001:0DB8:0001:0002:0:0:0:9'), bucket);
        assert.equal(plugin.clientBucket('2001:db8:1:2::192.0.2.7'), bucket);
        assert.equal(plugin.clientBucket('2001:db8::1'), '2001:db8:0:0::/64');
        assert.equal(plugin.clientBucket('2001:db8:1:3::1') === bucket, false);
    });
});

describe('limit-upstash', () => {
    const instance = Object.create(plugin);
    Object.assign(instance, {
        config: { get: () => ({ main: { rate_limit_window: '60', rate_limit_count: '2', max_rejected_rcpts: '3' } }) },
        register_hook() {},
        loginfo() {},
        logerror() {},
    });

    before(() => plugin.register.call(instance));
    after(() => plugin.shutdown.call(instance));

    async function connect(ip) {
        let code;
        await plugin.check_limit.call(instance, (c) => { code = c; }, { remote: { ip } });
        return code;
    }

    function rcpt(ip, rejected) {
        let code;
        plugin.check_rcpt_limit.call(instance, (c) => { code = c; }, { remote: { ip }, rcpt_count: { reject: rejected } });
        return code;
    }

    it('limits connections per IPv6 /64, not per address (in-memory fallback)', async () => {
        assert.equal(await connect('2001:db8:5:5::1'), undefined);
        assert.equal(await connect('2001:db8:5:5::2'), undefined);
        assert.equal(await connect('2001:db8:5:5::3'), DENYSOFT);
        assert.equal(await connect('2001:db8:5:6::1'), undefined, 'another /64 has its own limit');
    });

    it('never limits localhost', async () => {
        for (let i = 0; i < 5; i++) assert.equal(await connect('127.0.0.1'), undefined);
    });

    it('disconnects once a connection has had max_rejected_rcpts rejected recipients', () => {
        assert.equal(rcpt('192.0.2.1', 0), undefined);
        assert.equal(rcpt('192.0.2.1', 2), undefined);
        assert.equal(rcpt('192.0.2.1', 3), DENYSOFTDISCONNECT);
        assert.equal(rcpt('::1', 50), undefined, 'not for localhost');
    });
});
