'use strict';

const { Readable } = require('node:stream');
const Address = require('address-rfc2821').Address;
const addressRfc2822 = require('address-rfc2822');
const srs = require('../lib/srs');
const pgpEncrypt = require('../lib/pgp-encrypt');
const pgpMime = require('../lib/pgp-mime');
const db = require('../lib/db');
const replyToken = require('../lib/reply-token');
let outbound;

function getRawMessage(txn) {
    return new Promise((resolve) => {
        txn.message_stream.get_data((buf) => {
            resolve(Buffer.isBuffer(buf) ? buf : Buffer.from(buf));
        });
    });
}

function prepareOutboundContents(contents) {
    if (Buffer.isBuffer(contents)) {
        return Readable.from([contents]);
    }

    return contents;
}

function parseHeaderAddress(value) {
    if (!value) return null;

    try {
        const parsed = addressRfc2822.parse(value);
        const first = Array.isArray(parsed) ? parsed.find(entry => entry?.address) : null;
        return first?.address || null;
    } catch (_err) {
        return null;
    }
}

function getOriginalSenderAddress(txn) {
    return parseHeaderAddress(txn?.header?.get('Reply-To'))
        || parseHeaderAddress(txn?.header?.get('From'))
        || txn?.mail_from?.address()
        || null;
}

function replaceReplyToHeader(rawMessage, replyTo) {
    if (!replyTo) return rawMessage;

    const eoh = rawMessage.indexOf('\r\n\r\n');
    if (eoh === -1) return rawMessage;

    const headerBlock = rawMessage.subarray(0, eoh).toString('utf8');
    const body = rawMessage.subarray(eoh + 4);
    const headers = [];
    let currentHeader = null;

    for (const line of headerBlock.split('\r\n')) {
        if (/^[ \t]/.test(line)) {
            if (currentHeader !== null) currentHeader += `\r\n${line}`;
            continue;
        }

        if (currentHeader !== null) headers.push(currentHeader);
        currentHeader = line;
    }

    if (currentHeader !== null) headers.push(currentHeader);

    const nextHeaders = headers.filter(header => !/^Reply-To:/i.test(header));
    nextHeaders.push(`Reply-To: ${replyTo}`);

    return Buffer.concat([
        Buffer.from(`${nextHeaders.join('\r\n')}\r\n\r\n`),
        body,
    ]);
}

function sendEmail(origin, from, to, contents, notes) {
    return new Promise((resolve, reject) => {
        outbound.send_email(from, to, prepareOutboundContents(contents), (code, msg) => {
            if (code === DENY || code === DENYSOFT) {
                reject(new Error(`send_email failed: ${msg}`));
            } else {
                resolve();
            }
        }, { notes, origin });
    });
}

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
            const originalSender = getOriginalSenderAddress(txn) || sender;
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
            if (aliasData.recipients.length > 0) {
                rawMessage = await getRawMessage(txn);
            }

            // Generate reply tokens and send PGP-encrypted copies via send_email
            const pgpSends = pgpRecipients.map(async (recipient) => {
                try {
                    // Generate per-recipient reply token (in-process AES-GCM, no I/O)
                    let replyTo;
                    try {
                        const token = replyToken.create(originalSender, aliasEmail, recipient.email);
                        replyTo = `${token}@reply.anon.li`;
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
                    await sendEmail(plugin, srsSender, recipient.email, fullMessage, { ...txn.notes });

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
                        const token = replyToken.create(originalSender, aliasEmail, recipient.email);
                        replyTo = `${token}@reply.anon.li`;
                    } catch (err) {
                        plugin.logerror(`Reply token failed for ${recipient.email}: ${err.message}`);
                    }

                    // Build a per-recipient copy without mutating the shared transaction.
                    const rawMsg = replaceReplyToHeader(rawMessage, replyTo);
                    await sendEmail(plugin, srsSender, recipient.email, rawMsg, { ...txn.notes });

                    plugin.loginfo(`Plain forwarded to ${recipient.email}`);
                });

                await Promise.all(plainSends);
            }

            // Record stats — fire-and-forget, do not block delivery
            db.incrementAliasStats(aliasData.id, { forwarded: 1 })
                .catch(err => plugin.logerror(`Stats update failed: ${err.message}`));

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

exports.prepareOutboundContents = prepareOutboundContents;
exports.getOriginalSenderAddress = getOriginalSenderAddress;
exports.replaceReplyToHeader = replaceReplyToHeader;
