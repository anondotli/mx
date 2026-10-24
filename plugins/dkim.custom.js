'use strict';

const { dkimSign } = require('mailauth');
const dkimKeys = require('../lib/dkim-keys');
const { readRawMessage } = require('../lib/raw-message');
const { OWN_DOMAIN } = require('../lib/constants');

exports.register = function () {
    this.register_hook('pre_send_trans_email', 'sign_message');
};

exports.sign_message = async function (next, connection) {
    const plugin = this;
    const txn = connection.transaction;
    if (!txn) return next();

    try {
        // Sign as the domain we put in From (a custom-domain alias on replies
        // and DMARC-munged forwards); everything else is signed as anon.li.
        // Never derive this from message content, or a spoofed From would get
        // a customer domain's signature.
        let domain = txn.notes?.dkim_domain || OWN_DOMAIN;
        let keyData = await this.get_key(domain);
        if (!keyData && domain !== OWN_DOMAIN) {
            domain = OWN_DOMAIN;
            keyData = await this.get_key(domain);
        }
        if (!keyData) {
            plugin.logwarn(`DKIM signing skipped for ${txn.uuid}: no key for ${domain}`);
            return next();
        }

        // Sign the exact bytes that will be transmitted (relaxed/relaxed,
        // mailauth's default header set), so the signature cannot drift from
        // what Haraka emits — folded or unusual header lines included.
        const { signatures, errors } = await dkimSign(await readRawMessage(txn), {
            canonicalization: 'relaxed/relaxed',
            algorithm: 'rsa-sha256',
            signatureData: [{
                signingDomain: domain,
                selector: keyData.selector,
                privateKey: keyData.privateKey,
            }],
        });
        if (errors?.length) throw errors[0].err || new Error(errors[0].message || 'signing failed');

        const header = signatures.trim();
        const colon = header.indexOf(':');
        txn.add_leading_header(header.slice(0, colon).trim(), header.slice(colon + 1).trim());

        next();
    } catch (err) {
        plugin.logerror(`DKIM Error: ${err.message}`);
        next(); // Don't fail mail on signing error
    }
};

exports.get_key = function (domain) {
    return dkimKeys.getKey(domain, this.config, (msg) => this.logerror(msg));
};
