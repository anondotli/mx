'use strict';

const srs = require('../lib/srs');
const bounceToken = require('../lib/bounce-token');

exports.register = function () {
    this.register_hook('rcpt', 'check_bounce');
};

exports.check_bounce = async function (next, connection, params) {
    const txn = connection.transaction;
    if (!txn) return next();

    const rcpt = params[0];
    if (!rcpt.address()) return next();

    const email = rcpt.address();
    const localPart = email.split('@')[0];
    const upper = localPart.toUpperCase();

    const isSrs = upper.startsWith('SRS0=') || upper.startsWith('SRS1=');
    const isToken = upper.startsWith(bounceToken.ADDRESS_PREFIX);

    // Only intercept SRS and tokenised bounce addresses
    if (!isSrs && !isToken) return next();

    // Reject mixed-mode transactions
    if (txn.notes.alias || txn.notes.reply || txn.notes.zoho_relay || txn.notes.bounce) {
        return next(DENY, 'Mixed recipient types not allowed');
    }

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
        txn.notes.bounce = { originalSender: result.originalSender };
        this.loginfo(`Bounce token validated: ${email} → ${result.originalSender}`);
        return next(OK);
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

    txn.notes.bounce = { originalSender: result.originalSender };
    this.loginfo(`SRS bounce validated: ${email} → ${result.originalSender}`);
    return next(OK);
};
