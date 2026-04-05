'use strict';

const fs = require('fs');
const path = require('path');
const { sealMessage } = require('mailauth');

exports.register = function () {
    this.register_hook('pre_send_trans_email', 'seal_message');
};

exports.seal_message = async function (next, connection) {
    const plugin = this;
    const txn = connection.transaction;
    if (!txn) return next();

    // Only ARC-sign forwarded mail
    if (!txn.notes.alias && !txn.notes.zoho_relay) return next();

    try {
        const auth = txn.notes.mailauth;
        if (!auth) return next();

        // Build Authentication-Results string from mailauth data
        const arParts = [];
        if (auth.spf?.status?.result) {
            arParts.push(`spf=${auth.spf.status.result}`);
        }
        if (auth.dkim?.results?.length) {
            for (const r of auth.dkim.results) {
                arParts.push(`dkim=${r.status?.result || 'none'}`);
            }
        }
        if (auth.dmarc?.status?.result) {
            arParts.push(`dmarc=${auth.dmarc.status.result}`);
        }
        if (arParts.length === 0) return next();

        const authResults = `mx.anon.li; ${arParts.join('; ')}`;

        // Determine cv (chain validation) for ARC-Seal per RFC 8617 §4.1.4
        // 'none' = no previous chain, 'pass' = prior chain valid, 'fail' = prior chain invalid
        let cv = 'none';
        if (auth.arc?.status?.result === 'pass') {
            cv = 'pass';
        } else if (auth.arc?.status?.result === 'fail') {
            cv = 'fail';
        }

        // Load DKIM private key for ARC signing (same key as DKIM)
        const keyPath = path.resolve(__dirname, '..', 'config', 'dkim', 'anon.li', 'private');
        let privateKey;
        try {
            privateKey = fs.readFileSync(keyPath, 'utf8');
        } catch (_e) {
            plugin.logwarn(`ARC signing skipped: no DKIM key at ${keyPath}`);
            return next();
        }

        const cfg = plugin.config.get('dkim_sign.ini');
        const selector = cfg['domain anon.li']?.selector || 'default';

        // Get raw message for sealing
        const rawMessage = await new Promise((resolve) => {
            txn.message_stream.get_data((buf) => resolve(buf));
        });

        const sealHeaders = await sealMessage(rawMessage, {
            signingDomain: 'anon.li',
            selector,
            privateKey,
            authResults,
            algorithm: 'rsa-sha256',
            cv,
        });

        // Add ARC headers to the message
        if (sealHeaders && sealHeaders.length > 0) {
            const headerStr = sealHeaders.toString().trim();
            // Parse individual ARC headers and add them
            for (const line of headerStr.split(/\r?\n(?=[A-Z])/)) {
                const colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    const name = line.substring(0, colonIdx).trim();
                    const value = line.substring(colonIdx + 1).trim();
                    txn.add_leading_header(name, value);
                }
            }
        }

        next();
    } catch (err) {
        plugin.logerror(`ARC signing error: ${err.message}`);
        next(); // Don't fail mail on ARC signing error
    }
};
