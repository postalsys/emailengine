'use strict';

const crypto = require('crypto');
const assert = require('assert');

const WD_ENCRYPTION_SCHEME_KEY_1 = 'wd01';
const WD_CIPHER_1 = 'aes-256-gcm';

// defaults
const WD_ENCRYPTION_SCHEME = WD_ENCRYPTION_SCHEME_KEY_1;
const WD_CIPHER = WD_CIPHER_1;

// Store cached password keys in a Weak Map to prevent accidental leakage
const CACHED_KEYS_WM = new WeakMap();
// We will keep the weak map keys (Buffer values) in this Map
const CACHED_SALT_OBJ = new Map();
// Max items to keep in the LRU cache
const LRU_CACHE_MAX = 1500;

// Simple LRU cache for storing secrets in a WeakMap
function saltCache(password, salt, key) {
    const cacheKeyStr = crypto.createHmac('sha256', password).update(salt).digest('hex');

    // Get path
    if (!key) {
        const cacheKeyObj = CACHED_SALT_OBJ.get(cacheKeyStr);
        if (!cacheKeyObj) {
            return; // nothing known
        }
        const existing = CACHED_KEYS_WM.get(cacheKeyObj);
        if (!existing) {
            return; // no derived key cached
        }

        // Bump recency for the found key
        CACHED_SALT_OBJ.delete(cacheKeyStr);
        CACHED_SALT_OBJ.set(cacheKeyStr, cacheKeyObj);
        return existing;
    }

    // Set path: we know we’re storing a new key
    let cacheKeyObj = CACHED_SALT_OBJ.get(cacheKeyStr) || salt;
    CACHED_KEYS_WM.set(cacheKeyObj, key);

    // Bump/inject into recency Map
    CACHED_SALT_OBJ.delete(cacheKeyStr);
    CACHED_SALT_OBJ.set(cacheKeyStr, cacheKeyObj);

    // Evict oldest if over capacity
    if (CACHED_SALT_OBJ.size > LRU_CACHE_MAX) {
        const oldestKeyStr = CACHED_SALT_OBJ.keys().next().value;
        const oldestSaltObj = CACHED_SALT_OBJ.get(oldestKeyStr);
        CACHED_SALT_OBJ.delete(oldestKeyStr);
        CACHED_KEYS_WM.delete(oldestSaltObj);
    }

    return key;
}

function parseEncryptedData(encryptedData) {
    encryptedData = (encryptedData || '').toString();
    if (!encryptedData || encryptedData.charAt(0) !== '$') {
        // cleartext
        return {
            format: 'cleartext',
            data: encryptedData
        };
    }

    let parts = encryptedData.split('$');

    let [, format, cipher, authTag, iv, salt, encryptedText] = parts;
    if (parts.length !== 7 || !format || !cipher || !authTag || !iv || !salt || !encryptedText) {
        // assume cleartext if format is not matching
        return {
            format: 'cleartext',
            data: encryptedData
        };
    }

    authTag = Buffer.from(authTag, 'hex');
    iv = Buffer.from(iv, 'hex');
    salt = Buffer.from(salt, 'hex');
    encryptedText = Buffer.from(encryptedText, 'hex');

    return {
        format,
        cipher,
        authTag,
        iv,
        salt,
        data: encryptedText
    };
}

function getKeyFromPassword(password, salt) {
    let cachedKey = saltCache(password, salt);
    if (cachedKey) {
        return cachedKey;
    }
    const key = crypto.scryptSync(password, salt, 32);
    saltCache(password, salt, key); // update cache
    return key;
}

function decrypt(encryptedData, secret) {
    const raw = (encryptedData || '').toString('utf-8');

    if (!secret || !raw) {
        return raw;
    }

    const decryptData = parseEncryptedData(raw);

    switch (decryptData.format) {
        case 'cleartext':
            return raw;

        case WD_ENCRYPTION_SCHEME_KEY_1:
            try {
                assert.strictEqual(decryptData.authTag.length, 16, 'Invalid auth tag length');
                assert.strictEqual(decryptData.iv.length, 12, 'Invalid iv length');
                assert.strictEqual(decryptData.salt.length, 16, 'Invalid salt length');
                assert.strictEqual(decryptData.cipher, WD_CIPHER_1, 'Unsupported cipher');

                // convert password to 32B key
                const key = getKeyFromPassword(secret, decryptData.salt);

                const decipher = crypto.createDecipheriv(decryptData.cipher, key, decryptData.iv, {
                    authTagLength: decryptData.authTag.length
                });
                decipher.setAuthTag(decryptData.authTag);

                // try to decipher
                return Buffer.concat([decipher.update(decryptData.data), decipher.final()]).toString('utf-8');
            } catch (E) {
                let err = new Error('Failed to decrypt data. ' + E.message);
                err.responseCode = 500;
                err.code = 'InternalConfigError';
                throw err;
            }

        default: {
            // assume cleartext
            return raw;
        }
    }
}

function encrypt(cleartext, secret) {
    if (!secret || !cleartext) {
        return cleartext;
    }

    const iv = crypto.randomBytes(12);
    const salt = crypto.randomBytes(16);

    const key = getKeyFromPassword(secret, salt);

    const format = WD_ENCRYPTION_SCHEME;
    const algo = WD_CIPHER;

    const cipher = crypto.createCipheriv(algo, key, iv, { authTagLength: 16 });
    const encryptedText = Buffer.concat([cipher.update(cleartext), cipher.final()]);

    const authTag = cipher.getAuthTag();

    return ['', format, algo].concat([authTag, iv, salt, encryptedText].map(buf => buf.toString('hex'))).join('$');
}

module.exports = { encrypt, decrypt, parseEncryptedData };
