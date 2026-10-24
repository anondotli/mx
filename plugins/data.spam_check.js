'use strict';

const db = require('../lib/db');

exports.register = function () {
    this.register_hook('data_post', 'spam_check');
};

function hasPassingDkim(auth) {
    const dkimResults = auth?.dkim?.results || [];
    return dkimResults.some(r => r.status?.result === 'pass');
}

// Counts a rejected message against the alias (dashboard "blocked" stat).
function recordBlocked(plugin, txn) {
    const aliasId = txn.notes.alias?.id;
    if (!aliasId) return;
    db.incrementAliasStats(aliasId, { blocked: 1 })
        .catch(err => plugin.logerror(`Stats update failed: ${err.message}`));
}

exports.spam_check = function (next, connection) {
    const txn = connection.transaction;
    if (!txn) return next();

    // Skip trusted paths
    if (txn.notes.is_reply) return next();
    if (txn.notes.purelymail_relay) return next();

    const auth = txn.notes.mailauth;
    if (!auth) return next();

    // DMARC reject: refused here, as a direct delivery would be at the
    // recipient's provider. Forwarded, it would bounce there unseen (the DSN is
    // suppressed) — queue.forward only rewrites From for mail that passed.
    if (auth.dmarc?.status?.result === 'fail' && auth.dmarc?.policy === 'reject') {
        this.loginfo(`DMARC reject: ${txn.mail_from.address}`);
        recordBlocked(this, txn);
        return next(DENY, 'Message failed DMARC policy (reject)');
    }

    // DMARC quarantine — flag but deliver; the forward keeps its From, so the
    // recipient's provider applies the quarantine policy itself
    if (auth.dmarc?.status?.result === 'fail' && auth.dmarc?.policy === 'quarantine') {
        this.loginfo(`DMARC quarantine: ${txn.mail_from.address}`);
        txn.add_header('X-Spam-Flag', 'YES');
        txn.add_header('X-Spam-Reason', 'DMARC fail (policy=quarantine)');
    }

    // SPF hard fail + no passing DKIM
    if (auth.spf?.status?.result === 'fail') {
        if (!hasPassingDkim(auth)) {
            this.loginfo(`SPF fail + no DKIM pass: ${txn.mail_from.address}`);
            recordBlocked(this, txn);
            return next(DENY, 'Message failed SPF with no valid DKIM');
        }
    }

    return next();
};

exports.hasPassingDkim = hasPassingDkim;
