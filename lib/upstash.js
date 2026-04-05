'use strict';

let redis = null;

if (process.env.UPSTASH_REDIS_REST_URL) {
    try {
        const { Redis } = require('@upstash/redis');
        redis = new Redis({
            url: process.env.UPSTASH_REDIS_REST_URL,
            token: process.env.UPSTASH_REDIS_REST_TOKEN,
        });
    } catch (_e) { /* @upstash/redis not available */ }
}

module.exports = redis;
