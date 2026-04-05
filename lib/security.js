'use strict';

const crypto = require('crypto');

/**
 * Constant-time string comparison
 */
function constantTimeCompare(a, b) {
    if (!a || !b) return false;
    try {
        const bufA = Buffer.from(a);
        const bufB = Buffer.from(b);
        if (bufA.length !== bufB.length) return false;
        return crypto.timingSafeEqual(bufA, bufB);
    } catch (_err) {
        return false;
    }
}

/**
 * Validate email address format (RFC 5322 simplified)
 */
function validateEmailFormat(email) {
    if (!email || typeof email !== 'string') return false;
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email) && email.length <= 320;
}

/**
 * Validate domain name
 */
function validateDomainFormat(domain) {
    if (!domain || typeof domain !== 'string') return false;
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) return false;
    if (domain.startsWith('.') || domain.startsWith('-')) return false;
    if (domain.endsWith('.') || domain.endsWith('-')) return false;
    if (domain.includes('..')) return false;
    return domain.length <= 253;
}

/**
 * Validate list of domains
 */
function validateDomainList(domains) {
    if (!Array.isArray(domains)) return ['anon.li'];
    return domains.filter(d => validateDomainFormat(d));
}

/**
 * Per-key circuit breakers — isolate failures so a stats outage
 * doesn't block alias validation, etc.
 */
const circuitBreakers = new Map();

function getBreaker(key) {
    if (!circuitBreakers.has(key)) {
        circuitBreakers.set(key, {
            state: 'closed',       // closed = normal, open = failing, half-open = testing
            failures: 0,
            threshold: 5,          // open after 5 consecutive failures
            resetTimeout: 30000,   // try again after 30s
            lastFailure: 0,
        });
    }
    return circuitBreakers.get(key);
}

/**
 * Retry wrapper with per-key circuit breaker for API calls
 * @param {Function} fn - async function receiving AbortSignal
 * @param {object} [opts] - options
 * @param {number} [opts.retries=3]
 * @param {number} [opts.timeout=5000]
 * @param {string} [opts.breakerKey='default']
 */
async function retryCall(fn, opts = {}) {
    // Support legacy positional args: retryCall(fn, retries, timeout)
    if (typeof opts === 'number') {
        opts = { retries: opts, timeout: arguments[2] };
    }
    const { retries = 3, timeout = 5000, breakerKey = 'default' } = opts;
    const breaker = getBreaker(breakerKey);

    // Circuit breaker check
    if (breaker.state === 'open') {
        if (Date.now() - breaker.lastFailure > breaker.resetTimeout) {
            breaker.state = 'half-open';
        } else {
            throw new Error(`Circuit breaker open (${breakerKey}) — API unavailable`);
        }
    }

    for (let i = 0; i < retries; i++) {
        try {
            const controller = new AbortController();
            const id = setTimeout(() => controller.abort(), timeout);
            const result = await fn(controller.signal);
            clearTimeout(id);
            // Success — reset circuit breaker
            breaker.failures = 0;
            breaker.state = 'closed';
            return result;
        } catch (err) {
            if (i === retries - 1) {
                // Final failure — update circuit breaker
                breaker.failures++;
                breaker.lastFailure = Date.now();
                if (breaker.failures >= breaker.threshold) {
                    breaker.state = 'open';
                }
                throw err;
            }
            await new Promise(r => setTimeout(r, 1000 * Math.pow(2, i))); // Exponential backoff
        }
    }
}

module.exports = {
    constantTimeCompare,
    validateEmailFormat,
    validateDomainFormat,
    validateDomainList,
    retryCall
};
