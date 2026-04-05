'use strict';

const crypto = require('crypto');
const openpgp = require('openpgp');

const keyCache = new Map();
const KEY_CACHE_TTL = 3600000; // 1 hour

async function getPublicKey(armoredKey) {
    if (!armoredKey) throw new Error('No public key');

    // Cache check — use SHA-256 of the full key to avoid prefix collisions
    const cacheKey = crypto.createHash('sha256').update(armoredKey).digest('hex');
    const cached = keyCache.get(cacheKey);
    if (cached && cached.expires > Date.now()) return cached.key;

    // Parse (v6 API change: readKey is async)
    const publicKey = await openpgp.readKey({ armoredKey });
    
    // Validate Expiration
    const expirationTime = await publicKey.getExpirationTime();
    if (expirationTime && expirationTime < new Date()) {
        throw new Error('Key expired');
    }

    // Cache
    keyCache.set(cacheKey, {
        key: publicKey,
        expires: Date.now() + KEY_CACHE_TTL
    });

    return publicKey;
}

exports.encryptMime = async function(mimeBuffer, publicKeyArmored) {
    try {
        const publicKey = await getPublicKey(publicKeyArmored);
        const message = await openpgp.createMessage({
            binary: new Uint8Array(mimeBuffer),
        });

        const encrypted = await openpgp.encrypt({
            message,
            encryptionKeys: publicKey,
            format: 'armored',
        });

        return encrypted;
    } catch (err) {
        throw new Error(`PGP Encryption failed: ${err.message}`, { cause: err });
    }
};

exports.encryptBody = async function(text, publicKeyArmored) {
    try {
        const publicKey = await getPublicKey(publicKeyArmored);
        // v6 API: createMessage is async
        const message = await openpgp.createMessage({ text });
        
        const encrypted = await openpgp.encrypt({
            message,
            encryptionKeys: publicKey,
            format: 'armored'
        });
        
        return encrypted;
    } catch (err) {
        throw new Error(`PGP Encryption failed: ${err.message}`, { cause: err });
    }
};
