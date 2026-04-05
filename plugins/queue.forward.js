'use strict';

const { fetch } = require('undici');
const Address = require('address-rfc2821').Address;
const srs = require('../lib/srs');
const pgpEncrypt = require('../lib/pgp-encrypt');
const pgpMime = require('../lib/pgp-mime');
const { retryCall } = require('../lib/security');
let outbound;

exports.register = function () {
    outbound = this.haraka_require('outbound');
    this.register_hook('queue', 'process_forward');
    this.register_hook('get_mx', 'route_zoho_mx');
};

// Override MX resolution for reserved aliases
// Without this, anon.li MX → mx.anon.li (ourselves) would create a loop.
exports.route_zoho_mx = function (next, hmail, _domain) {
    if (hmail?.todo?.notes?.zoho_mx) {
        return next(OK, [
            { priority: 10, exchange: 'mx.zoho.eu' },
            { priority: 20, exchange: 'mx2.zoho.eu' },
            { priority: 50, exchange: 'mx3.zoho.eu' },
        ]);
    }
    return next();
};

exports.process_forward = async function (next, connection) {
    const plugin = this;
    const txn = connection.transaction;
    if (!txn) return next();

    const aliasData = txn.notes.alias;
    const replyData = txn.notes.reply;
    if (txn.notes.zoho_relay) {
        txn.notes.zoho_mx = true;
        const sender = txn.mail_from.address();
        if (sender) {
            const srsSecret = process.env.MAIL_API_SECRET;
            const srsSender = srs.rewrite(sender, 'anon.li', srsSecret);
            txn.mail_from = new Address(srsSender);
        }
        plugin.loginfo(`Zoho relay: ${txn.notes.zoho_recipient}`);
        return outbound.send_trans_email(txn, next);
    }

    const bounceData = txn.notes.bounce;

    if (!aliasData && !replyData && !bounceData) return next();

    try {
        if (aliasData) {
            // == FORWARD MODE ==
            const sender = txn.mail_from.address();
            const aliasEmail = txn.rcpt_to[0].address();

            // Rewrite envelope sender using SRS
            const srsSecret = process.env.MAIL_API_SECRET;
            const srsSender = srs.rewrite(sender, 'anon.li', srsSecret);
            txn.mail_from = new Address(srsSender);

            txn.add_header('X-Anon-Forward', 'true');

            // Partition recipients into PGP-enabled and plain groups
            const pgpRecipients = aliasData.recipients.filter(r => r.pgpPublicKey);
            const plainRecipients = aliasData.recipients.filter(r => !r.pgpPublicKey);

            // Extract raw message once for PGP/MIME encryption
            let rawMessage;
            if (pgpRecipients.length > 0) {
                rawMessage = await new Promise((resolve) => {
                    txn.message_stream.get_data((buf) => {
                        resolve(Buffer.isBuffer(buf) ? buf : Buffer.from(buf));
                    });
                });
            }

            // Generate reply tokens and send PGP-encrypted copies via send_email
            const pgpSends = pgpRecipients.map(async (recipient) => {
                try {
                    // Generate per-recipient reply token
                    let replyTo;
                    try {
                        const tokenData = await retryCall(async (signal) => {
                            const res = await fetch(`${process.env.FRONTEND_URL}/api/internal/reply-token`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'x-api-secret': process.env.MAIL_API_SECRET,
                                },
                                body: JSON.stringify({
                                    originalSender: sender,
                                    aliasEmail,
                                    recipientEmail: recipient.email,
                                }),
                                signal,
                            });
                            if (!res.ok) throw new Error(`API ${res.status}`);
                            return res.json();
                        }, { breakerKey: 'reply-token' });
                        if (tokenData?.token) {
                            replyTo = `${tokenData.token}@reply.anon.li`;
                        }
                    } catch (err) {
                        plugin.logerror(`Reply token failed for ${recipient.email}: ${err.message}`);
                    }

                    // Build PGP/MIME message
                    const { transportHeaders, mimeEntity } = pgpMime.extractMimeEntity(rawMessage);
                    const encryptedArmor = await pgpEncrypt.encryptMime(mimeEntity, recipient.pgpPublicKey);

                    // Inject Reply-To into transport headers if we have a token
                    let headers = transportHeaders;
                    if (replyTo) {
                        // Remove any existing Reply-To and add ours
                        headers = headers.split('\r\n')
                            .filter(l => !/^Reply-To:/i.test(l))
                            .join('\r\n');
                        headers += `\r\nReply-To: ${replyTo}`;
                    }

                    const fullMessage = pgpMime.buildPgpMimeMessage(headers, encryptedArmor);

                    // Send via outbound.send_email (creates a fresh transaction)
                    await new Promise((resolve, reject) => {
                        outbound.send_email(srsSender, recipient.email, fullMessage, (code, msg) => {
                            if (code === DENY || code === DENYSOFT) {
                                reject(new Error(`send_email failed: ${msg}`));
                            } else {
                                resolve();
                            }
                        }, { notes: { ...txn.notes } });
                    });

                    plugin.loginfo(`PGP/MIME encrypted and sent to ${recipient.email}`);
                } catch (pgpErr) {
                    plugin.logwarn(`PGP/MIME failed for ${recipient.email}, sending unencrypted: ${pgpErr.message}`);
                    // Fall back: add to plain recipients list
                    plainRecipients.push(recipient);
                }
            });

            await Promise.all(pgpSends);

            // For plain recipients (and PGP fallbacks): send each with its own reply token
            if (plainRecipients.length > 0) {
                const plainSends = plainRecipients.map(async (recipient) => {
                    let replyTo;
                    try {
                        const tokenData = await retryCall(async (signal) => {
                            const res = await fetch(`${process.env.FRONTEND_URL}/api/internal/reply-token`, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'x-api-secret': process.env.MAIL_API_SECRET,
                                },
                                body: JSON.stringify({
                                    originalSender: sender,
                                    aliasEmail,
                                    recipientEmail: recipient.email,
                                }),
                                signal,
                            });
                            if (!res.ok) throw new Error(`API ${res.status}`);
                            return res.json();
                        }, { breakerKey: 'reply-token' });
                        if (tokenData?.token) {
                            replyTo = `${tokenData.token}@reply.anon.li`;
                        }
                    } catch (err) {
                        plugin.logerror(`Reply token failed for ${recipient.email}: ${err.message}`);
                    }

                    // Clone headers with per-recipient Reply-To
                    if (replyTo) {
                        txn.remove_header('Reply-To');
                        txn.add_header('Reply-To', replyTo);
                    }

                    // Send individually via send_email for recipient isolation
                    const rawMsg = await new Promise((resolve) => {
                        txn.message_stream.get_data((buf) => resolve(buf));
                    });

                    await new Promise((resolve, reject) => {
                        outbound.send_email(srsSender, recipient.email, rawMsg, (code, msg) => {
                            if (code === DENY || code === DENYSOFT) {
                                reject(new Error(`send_email failed: ${msg}`));
                            } else {
                                resolve();
                            }
                        }, { notes: { ...txn.notes } });
                    });

                    plugin.loginfo(`Plain forwarded to ${recipient.email}`);
                });

                await Promise.all(plainSends);
            }

            // Record stats — fire-and-forget with retry, do not block delivery
            retryCall(async (signal) => {
                const res = await fetch(`${process.env.FRONTEND_URL}/api/internal/aliases`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-api-secret': process.env.MAIL_API_SECRET,
                    },
                    body: JSON.stringify({ aliasId: aliasData.id, forwarded: 1 }),
                    signal,
                });
                if (!res.ok) throw new Error(`Stats ${res.status}`);
            }, { breakerKey: 'stats' }).catch(err => plugin.logerror(`Stats update failed after retries: ${err.message}`));

            // All recipients sent individually via send_email
            plugin.loginfo(`Forwarding ${txn.uuid} (forward)`);
            return next(OK);

        } else if (replyData) {
            // == REPLY MODE ==
            const recipient = replyData.originalSender;

            // Rewrite From header to be the Alias
            txn.remove_header('From');
            txn.add_header('From', replyData.aliasEmail);

            // Rewrite To header — remove the reply token address, show the real recipient
            txn.remove_header('To');
            txn.add_header('To', recipient);

            // Store alias domain for DKIM signing (SRS rewrites envelope to @anon.li)
            const aliasDomain = replyData.aliasEmail.split('@')[1];
            if (aliasDomain && aliasDomain !== 'anon.li') {
                txn.notes.reply_dkim_domain = aliasDomain;
            }

            // Rewrite envelope sender using SRS so bounces route back correctly
            const srsSecret = process.env.MAIL_API_SECRET;
            const srsSender = srs.rewrite(replyData.aliasEmail, 'anon.li', srsSecret);
            txn.mail_from = new Address(srsSender);

            txn.rcpt_to = [new Address(recipient)];

        } else if (bounceData) {
            // == BOUNCE MODE ==
            // SRS bounce: route back to the original sender with empty return-path
            txn.mail_from = new Address('<>');
            txn.rcpt_to = [new Address(bounceData.originalSender)];
        }

        const mode = aliasData ? 'forward' : replyData ? 'reply' : 'bounce';
        plugin.loginfo(`Forwarding ${txn.uuid} (${mode})`);
        outbound.send_trans_email(txn, next);

    } catch (err) {
        plugin.logerror(err);
        next(DENYSOFT, 'Forwarding error');
    }
};
