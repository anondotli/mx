'use strict';

const { Address } = require('address-rfc2821');
const db = require('../lib/db');
const rcptPolicy = require('../lib/rcpt-policy');
const replyToken = require('../lib/reply-token');
const { REPLY_DOMAIN } = require('../lib/constants');
const { domainOf, sameMailbox, firstMailbox } = require('../lib/address');

exports.register = function () {
    this.register_hook('rcpt', 'check_reply_token');
    // After haraka-plugin-mailauth's data_post (earlier in config/plugins)
    this.register_hook('data_post', 'check_reply_sender');
};

exports.check_reply_token = async function (next, connection, params) {
    const txn = connection.transaction;
    if (!txn) return next();

    const email = params[0]?.address();
    if (!email || !email.toLowerCase().endsWith(`@${REPLY_DOMAIN}`)) return next();

    // One recipient per transaction (lib/rcpt-policy.js)
    if (rcptPolicy.answered(next, txn, email)) return;

    const token = email.slice(0, email.lastIndexOf('@'));
    let decoded;
    try {
        decoded = await replyToken.decode(token);
    } catch (err) {
        // Backing-store (Redis) error — tempfail so the sender retries instead
        // of permanently losing a valid reply.
        this.logerror(`Reply token lookup failed: ${err.message}`);
        return next(DENYSOFT, 'Temporary error, please retry');
    }
    if (!decoded) return next(DENY, 'Invalid reply token');

    try {
        new Address(decoded.originalSender);
    } catch (_err) {
        return next(DENY, 'The original sender cannot receive replies');
    }

    // The alias must still be ours to send as: deleted, taken-down or
    // superseded custom-domain aliases cannot keep replying through old tokens.
    let allowed;
    try {
        allowed = await db.canSendAs(decoded.aliasEmail);
    } catch (err) {
        this.logerror(`Reply alias lookup failed: ${err.message}`);
        return next(DENYSOFT, 'Temporary error, please retry');
    }
    if (!allowed) return next(DENY, 'This alias can no longer send mail');

    txn.notes.reply = {
        originalSender: decoded.originalSender,
        aliasEmail: decoded.aliasEmail,
        recipientEmail: decoded.recipientEmail,
    };
    txn.notes.is_reply = true;
    rcptPolicy.accept(txn, email);
    return next(OK);
};

function aligned(signingDomain, domain) {
    const a = String(signingDomain || '').toLowerCase();
    const b = String(domain || '').toLowerCase();
    return Boolean(a && b) && (a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`));
}

// The sender identities of a reply that mailauth authenticated:
// - the envelope sender when SPF passes: the sending provider's servers sent
//   it (DKIM proves only the domain and could be replayed under any envelope);
// - the From address when DMARC passes, or a passing DKIM signature aligns
//   with its domain — the signature covers From, so it cannot be replayed
//   under the owner's name.
function authenticatedSenders(txn) {
    const auth = txn.notes.mailauth || {};
    const senders = [];

    const envelope = txn.mail_from?.address() || '';
    if (envelope && auth.spf?.status?.result === 'pass') senders.push(envelope);

    const from = firstMailbox(txn.header.get('From'))?.address;
    if (from) {
        const dmarcPass = auth.dmarc?.status?.result === 'pass';
        const dkimAligned = (auth.dkim?.results || [])
            .some(r => r.status?.result === 'pass' && aligned(r.signingDomain, domainOf(from)));
        if (dmarcPass || dkimAligned) senders.push(from);
    }

    return senders;
}

// Replies go out signed as the alias, so only its owner may send them: an
// authenticated sender identity must be one of the owner's verified recipient
// addresses (the one the message was forwarded to, or another). A token alone
// is not enough — it is visible to anyone the forwarded copy reaches.
exports.check_reply_sender = async function (next, connection) {
    const txn = connection.transaction;
    const reply = txn?.notes?.reply;
    if (!reply) return next();

    const senders = authenticatedSenders(txn);
    if (senders.length === 0) {
        const spf = txn.notes.mailauth?.spf;
        if (!spf || spf.error || spf.status?.result === 'temperror') {
            return next(DENYSOFT, 'Could not verify the sender, please retry');
        }
        this.loginfo(`Unauthenticated reply to ${reply.aliasEmail} from <${txn.mail_from?.address() || ''}> refused`);
        return next(DENY, 'Replies must come from your own mailbox (SPF/DKIM did not verify)');
    }

    const ownedBy = (address) => senders.some(sender => sameMailbox(sender, address));
    if (ownedBy(reply.recipientEmail)) return next();

    let owner;
    try {
        owner = (await db.getOwnerAddresses(reply.aliasEmail)).some(ownedBy);
    } catch (err) {
        this.logerror(`Reply owner lookup failed: ${err.message}`);
        return next(DENYSOFT, 'Temporary error, please retry');
    }
    if (!owner) {
        this.loginfo(`Reply to ${reply.aliasEmail} from non-recipient sender ${senders.join(', ')} refused`);
        return next(DENY, 'Replies must be sent from one of your anon.li recipient addresses (add the address you reply from as a recipient)');
    }
    return next();
};
