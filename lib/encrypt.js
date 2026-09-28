'use strict';

// Encryption at rest for stored credentials (account passwords and tokens, the credential-bearing
// settings and account fields, webhook route targets, TLS private keys). A value is stored as
//
//     $wd01$aes-256-gcm$<authTag>$<iv>$<salt>$<ciphertext>      (every part hex)
//
// with the AES-256 key derived from the instance secret by scrypt(secret, salt). Derivation is the
// expensive part on purpose (it is what makes an offline brute force of the secret slow), so the
// derived key is cached per (secret, salt) pair in an LRU of LRU_CACHE_MAX entries.
//
// The salt is per PROCESS, not per value. Every value this process writes carries the same random
// salt and is therefore encrypted under one derived key, one cache entry, so a save or a hot-path
// decrypt of a recently written value never pays for a derivation after the first. Values used to
// get a salt each, which made the cache useless past LRU_CACHE_MAX stored values: the webhooks
// worker decrypts four fields per delivery, and past a few hundred accounts every delivery ran a
// cold scrypt (tens of milliseconds with the event loop blocked). Values written before this
// change keep their own salt and still decrypt through the same cache.
//
// Sharing a salt across values is safe because the salt protects nothing on its own: the KDF only
// stands between an attacker and the secret, and every value is encrypted under keys derived from
// that one secret, so a salt per value adds nothing against a brute force of it. What must never
// repeat under one key is the AES-GCM IV, and that stays random per value: 96 random bits collide
// with negligible probability for far more values than an instance will ever hold. The salt is
// random rather than derived from the secret for two reasons: a fast derivation (an HMAC of the
// secret, say) would let an attacker holding the ciphertexts test a candidate secret at the cost of
// one HMAC instead of one scrypt, and a slow one keyed on a fixed label would make the salt a
// deterministic function of the secret, so a table computed once could be checked against every
// instance. A random salt reveals nothing and costs the attacker the same scrypt per guess as before.

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

const SALT_LENGTH = 16;
const IV_LENGTH = 12;

// The salt every value written by this process carries, see the note at the top. Generated on the
// first write rather than at load so a process that only reads never draws one.
let processSalt = null;

function getProcessSalt() {
    if (!processSalt) {
        processSalt = crypto.randomBytes(SALT_LENGTH);
    }
    return processSalt;
}

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

    // Set path: we know we're storing a new key. The WeakMap key is an object of this entry's
    // own, never the caller's salt buffer: every value this process writes shares one salt
    // buffer, so keying on it would let a key derived for one secret overwrite the key derived
    // for another under the same salt, and a value would then be encrypted or decrypted with
    // the wrong secret's key.
    let cacheKeyObj = CACHED_SALT_OBJ.get(cacheKeyStr) || Buffer.from(salt);
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
                assert.strictEqual(decryptData.iv.length, IV_LENGTH, 'Invalid iv length');
                assert.strictEqual(decryptData.salt.length, SALT_LENGTH, 'Invalid salt length');
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

    // Random per value: GCM is only secure while no IV repeats under a key, and every value this
    // process writes shares one key
    const iv = crypto.randomBytes(IV_LENGTH);
    const salt = getProcessSalt();

    // Cached after the first write of this process
    const key = getKeyFromPassword(secret, salt);

    const format = WD_ENCRYPTION_SCHEME;
    const algo = WD_CIPHER;

    const cipher = crypto.createCipheriv(algo, key, iv, { authTagLength: 16 });
    const encryptedText = Buffer.concat([cipher.update(cleartext), cipher.final()]);

    const authTag = cipher.getAuthTag();

    return ['', format, algo].concat([authTag, iv, salt, encryptedText].map(buf => buf.toString('hex'))).join('$');
}

/**
 * Encrypts a stored field for writing. Nothing to do without a secret, and an empty value is left
 * as it is: several fields use the empty string as a "cleared" marker.
 *
 * @param {String} value - Cleartext
 * @param {String} secret - Instance secret
 * @returns {String} The value as it is to be stored
 */
function encryptField(value, secret) {
    if (!secret || !value) {
        return value;
    }
    return encrypt(value, secret);
}

/**
 * Decrypts a stored field, or treats it as unset. A value that does not decrypt with this secret
 * (the secret was rotated without `emailengine encrypt`, the value is corrupt) is reported through
 * `onError` and read as undefined, so the field is missing rather than the whole record failing.
 * Cleartext (a value stored before its field was encrypted) passes through, as decrypt() does.
 *
 * @param {String} value - The stored value
 * @param {String} secret - Instance secret
 * @param {Function} [onError] - Called with the error when the value does not decrypt
 * @returns {String|undefined} The cleartext, or undefined when it could not be read
 */
function decryptField(value, secret, onError) {
    if (!secret || !value) {
        return value;
    }
    try {
        return decrypt(value, secret);
    } catch (err) {
        if (typeof onError === 'function') {
            onError(err);
        }
        return undefined;
    }
}

module.exports = { encrypt, decrypt, encryptField, decryptField, parseEncryptedData };
