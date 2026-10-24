'use strict';

const srs = require('../lib/srs');
const rcptPolicy = require('../lib/rcpt-policy');
const bounceToken = require('../lib/bounce-token');
const { OWN_DOMAIN } = require('../lib/constants');
const { splitAddress } = require('../lib/address');

exports.register = function () {
    this.register_hook('rcpt', 'check_bounce');
};

exports.check_bounce = async function (next, connection, params) {
    const txn = connection.transaction;
    if (!txn) return next();

    const rcpt = params[0];
    if (!rcpt?.address()) return next();

    const email = rcpt.address();
    const parts = splitAddress(email);
    if (!parts) return next();
    const localPart = parts.local;
    const upper = localPart.toUpperCase();

    const isSrs = upper.startsWith('SRS0=') || upper.startsWith('SRS1=');
    const isToken = upper.startsWith(bounceToken.ADDRESS_PREFIX);

    // Only intercept SRS and tokenised bounce addresses — which we only ever
    // mint at @anon.li
    if (!isSrs && !isToken) return next();
    if (parts.domain !== OWN_DOMAIN) return next();

    // One recipient per transaction (lib/rcpt-policy.js)
    if (rcptPolicy.answered(next, txn, email)) return;

    // Tokenised bounce address (long senders the SRS local-part couldn't hold):
    // resolve the original sender from the server-side store.
    if (isToken) {
        const token = localPart.slice(bounceToken.ADDRESS_PREFIX.length);
        let result;
        try {
            result = await bounceToken.decode(token);
        } catch (err) {
            // Backing-store outage: tempfail so the DSN retries rather than being
            // permanently rejected.
            this.logerror(`Bounce token lookup failed for ${email}: ${err.message}`);
            return next(DENYSOFT, 'Bounce validation temporarily unavailable');
        }
        if (!result) {
            this.loginfo(`Unknown/expired bounce token: ${email}`);
            return next(DENY, 'Invalid bounce address');
        }
        // A relayed return path only takes bounces and auto-replies (null
        // sender), not arbitrary mail from whoever saw it in a Return-Path.
        if (result.relay && !txn.mail_from?.isNull?.()) {
            return next(DENY, 'Only delivery notifications are accepted here');
        }
        return accept.call(this, next, txn, email, result.originalSender, result.relay);
    }

    const secret = process.env.MAIL_API_SECRET;
    if (!secret) {
        this.logerror('No MAIL_API_SECRET for SRS bounce validation');
        return next(DENYSOFT, 'Configuration error');
    }

    const result = srs.reverse(email, secret);

    if (!result.valid) {
        this.loginfo(`Invalid SRS bounce address: ${email}`);
        return next(DENY, 'Invalid bounce address');
    }

    // SRS return paths are only minted for forwarded mail and Purelymail relays
    return accept.call(this, next, txn, email, result.originalSender, false);
};

// Only return paths minted for replies are relayed (they lead back to one of
// our own aliases). Bounces and auto-replies for forwarded mail come from the
// alias owner's provider and name their real address, so queue.forward accepts
// and drops them.
function accept(next, txn, email, originalSender, relay) {
    txn.notes.bounce = { originalSender, relay };
    rcptPolicy.accept(txn, email);
    this.loginfo(`Bounce validated: ${email} → ${originalSender}${relay ? '' : ' (not relayed)'}`);
    return next(OK);
}
