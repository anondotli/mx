'use strict';

const { Readable } = require('node:stream');
const Address = require('address-rfc2821').Address;
const addressRfc2822 = require('address-rfc2822');
const srs = require('../lib/srs');
const pgpEncrypt = require('../lib/pgp-encrypt');
const pgpMime = require('../lib/pgp-mime');
const db = require('../lib/db');
const replyToken = require('../lib/reply-token');
const bounceToken = require('../lib/bounce-token');
let outbound;

const MAX_LOCAL_PART_OCTETS = 64; // RFC 5321 §4.5.3.1.1

// SRS-rewrite an envelope sender into @anon.li, falling back to a short
// server-side bounce token when the SRS local-part would exceed the RFC-5321
// 64-octet limit. SRS encodes the original address into the local-part, so long
// ESP/VERP bounce senders overflow it and address-rfc2821 throws — DENYSOFTing
// the entire forward. The returned address is always safe to hand to the Address
// constructor; over-length senders come back as BNC=<token>@anon.li, which
// rcpt_to.bounce resolves on the return path. See [[bounce-token]].
async function buildEnvelopeSender(sender, srsSecret) {
    const srsSender = srs.rewrite(sender, 'anon.li', srsSecret);
    const at = srsSender.lastIndexOf('@');
    const localPart = at === -1 ? srsSender : srsSender.slice(0, at);
    if (Buffer.byteLength(localPart, 'utf8') <= MAX_LOCAL_PART_OCTETS) {
        return srsSender;
    }
    const token = await bounceToken.create(sender);
    return `${bounceToken.ADDRESS_PREFIX}${token}@anon.li`;
}

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

// Drop every existing instance of headerName (including folded continuation
// lines) from a CRLF-joined header block, then append a single fresh instance.
function replaceHeaderInBlock(headerBlock, headerName, headerValue) {
    const matcher = new RegExp(`^${headerName}:`, 'i');
    const kept = [];
    let skipping = false;

    for (const line of headerBlock.split('\r\n')) {
        if (/^[ \t]/.test(line)) {
            // Continuation line: keep it only if its parent header was kept.
            if (!skipping) kept.push(line);
            continue;
        }
        skipping = matcher.test(line);
        if (!skipping) kept.push(line);
    }

    kept.push(`${headerName}: ${headerValue}`);
    return kept.join('\r\n');
}

function replaceRawHeader(rawMessage, headerName, headerValue) {
    const eoh = rawMessage.indexOf('\r\n\r\n');
    if (eoh === -1) return rawMessage;

    const headerBlock = rawMessage.subarray(0, eoh).toString('utf8');
    const body = rawMessage.subarray(eoh + 4);

    return Buffer.concat([
        Buffer.from(`${replaceHeaderInBlock(headerBlock, headerName, headerValue)}\r\n\r\n`),
        body,
    ]);
}

function replaceReplyToHeader(rawMessage, replyTo) {
    if (!replyTo) return rawMessage;
    return replaceRawHeader(rawMessage, 'Reply-To', replyTo);
}

function replaceFromHeader(rawMessage, from) {
    if (!from) return rawMessage;
    return replaceRawHeader(rawMessage, 'From', from);
}

// RFC 5322 display-name encoding: a quoted-string for plain ASCII, or an
// RFC 2047 base64 encoded-word when the name carries non-ASCII bytes.
function encodeFromDisplayName(name) {
    if (/^[\x20-\x7E]*$/.test(name)) {
        return `"${name.replace(/[\\"]/g, '\\$&')}"`;
    }
    return `=?UTF-8?B?${Buffer.from(name, 'utf8').toString('base64')}?=`;
}

// Forwarding breaks the original sender's DMARC: SRS moves the envelope to
// @anon.li (SPF no longer aligns) and tracking removal rewrites the body
// (original DKIM no longer validates). Senders that publish p=reject/quarantine
// therefore bounce at the receiver. Rewrite From onto the alias — a domain we
// DKIM-sign — so DMARC aligns, keeping the sender's display name. Replies still
// route through the Reply-To reply token.
function shouldMungeFrom(txn) {
    const policy = txn?.notes?.mailauth?.dmarc?.policy;
    return policy === 'reject' || policy === 'quarantine';
}

function buildMungedFrom(txn, aliasEmail) {
    let display = '';
    try {
        const parsed = addressRfc2822.parse(txn?.header?.get('From') || '');
        const first = Array.isArray(parsed) ? parsed.find(entry => entry?.address) : null;
        display = (first?.phrase || '').trim() || first?.address || '';
    } catch (_err) {
        display = '';
    }

    const phrase = display ? `${display} via anon.li` : 'Anonymous via anon.li';
    return `${encodeFromDisplayName(phrase)} <${aliasEmail}>`;
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

            // Rewrite envelope sender using SRS (falls back to a short bounce
            // token when the SRS address would exceed 64 octets)
            const srsSecret = process.env.MAIL_API_SECRET;
            const srsSender = await buildEnvelopeSender(sender, srsSecret);
            txn.mail_from = new Address(srsSender);

            txn.add_header('X-Anon-Forward', 'true');

            // Rewrite From onto the alias when the sender publishes a strict
            // DMARC policy, otherwise the forward bounces at the receiver.
            const mungedFrom = shouldMungeFrom(txn) ? buildMungedFrom(txn, aliasEmail) : null;
            if (mungedFrom) {
                plugin.loginfo(`DMARC ${txn.notes.mailauth.dmarc.policy} sender — rewriting From to align with ${aliasEmail}`);
            }

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
                        const token = await replyToken.create(originalSender, aliasEmail, recipient.email);
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
                        headers = replaceHeaderInBlock(headers, 'Reply-To', replyTo);
                    }
                    if (mungedFrom) {
                        headers = replaceHeaderInBlock(headers, 'From', mungedFrom);
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
                        const token = await replyToken.create(originalSender, aliasEmail, recipient.email);
                        replyTo = `${token}@reply.anon.li`;
                    } catch (err) {
                        plugin.logerror(`Reply token failed for ${recipient.email}: ${err.message}`);
                    }

                    // Build a per-recipient copy without mutating the shared transaction.
                    let rawMsg = replaceReplyToHeader(rawMessage, replyTo);
                    if (mungedFrom) rawMsg = replaceFromHeader(rawMsg, mungedFrom);
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
            const srsSender = await buildEnvelopeSender(replyData.aliasEmail, srsSecret);
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
exports.replaceFromHeader = replaceFromHeader;
exports.replaceHeaderInBlock = replaceHeaderInBlock;
exports.encodeFromDisplayName = encodeFromDisplayName;
exports.shouldMungeFrom = shouldMungeFrom;
exports.buildMungedFrom = buildMungedFrom;
exports.buildEnvelopeSender = buildEnvelopeSender;
