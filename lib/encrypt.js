'use strict';

// Encryption at rest for stored credentials (account passwords and tokens, the credential-bearing
// settings and account fields, webhook route targets, TLS private keys). A value is stored as
//
//     $wd01$aes-256-gcm$<authTag>$<iv>$<salt>$<ciphertext>      (every part hex)
//
// with the AES-256 key derived from the instance secret and the salt. Two schemes exist, told
// apart by the first part: wd01 derives the key with scrypt(secret, salt, 32) and wd02 with
// PBKDF2-HMAC-SHA256 over 600000 iterations (a count fixed by the scheme id, never stored, so
// changing it means a new scheme). Everything written is wd02: scrypt is not among the primitives
// an OpenSSL FIPS provider offers, PBKDF2 is the password-based KDF it approves of, and a host in
// FIPS mode could not start otherwise. A wd01 value written by an earlier release still decrypts,
// and any rewrite of it (a credential update, a settings save, `emailengine encrypt`) moves it to
// wd02. Nothing rewrites on read, so an instance about to be moved to a FIPS host runs
// `emailengine encrypt` first: once there, a wd01 value is unreadable. Derivation is the
// expensive part on purpose (it is what makes an offline brute force of the secret slow), so the
// derived key is cached per (scheme, secret, salt) in an LRU of LRU_CACHE_MAX entries.
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
const { promisify } = require('util');

// Looked up on each call rather than bound at load, so a test can count the derivations
const pbkdf2Async = (...args) => promisify(crypto.pbkdf2)(...args);
const scryptAsync = (...args) => promisify(crypto.scrypt)(...args);

const WD_ENCRYPTION_SCHEME_KEY_1 = 'wd01';
const WD_ENCRYPTION_SCHEME_KEY_2 = 'wd02';
const WD_CIPHER_1 = 'aes-256-gcm';

// The PBKDF2 parameters of wd02, shared with the export file encryption (lib/stream-encrypt.js).
// The iteration count follows the OWASP figure for SHA-256
const PBKDF2_ITERATIONS = 600000;
const PBKDF2_DIGEST = 'sha256';

// defaults
const WD_ENCRYPTION_SCHEME = WD_ENCRYPTION_SCHEME_KEY_2;
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

// The scheme is part of the cache key: a wd01 and a wd02 value sharing a salt derive different keys
// from the same secret
function cacheKeyFor(scheme, password, salt) {
    return crypto.createHmac('sha256', password).update(scheme).update(salt).digest('hex');
}

// Simple LRU cache for storing secrets in a WeakMap, keyed by cacheKeyFor()
function saltCache(cacheKeyStr, salt, key) {
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

function deriveKey(scheme, password, salt) {
    switch (scheme) {
        case WD_ENCRYPTION_SCHEME_KEY_1:
            return crypto.scryptSync(password, salt, 32);
        case WD_ENCRYPTION_SCHEME_KEY_2:
            return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, PBKDF2_DIGEST);
        default:
            throw new Error(`Unknown encryption scheme ${scheme}`);
    }
}

function getKeyFromPassword(scheme, password, salt) {
    const cacheKey = cacheKeyFor(scheme, password, salt);
    let cachedKey = saltCache(cacheKey, salt);
    if (cachedKey) {
        return cachedKey;
    }
    const key = deriveKey(scheme, password, salt);
    saltCache(cacheKey, salt, key); // update cache
    return key;
}

// Derivations in flight, so values sharing a salt (every value one process wrote) wait for one
// derivation instead of starting one each
const PENDING_KEYS = new Map();

function deriveKeyAsync(scheme, password, salt) {
    switch (scheme) {
        case WD_ENCRYPTION_SCHEME_KEY_1:
            return scryptAsync(password, salt, 32);
        case WD_ENCRYPTION_SCHEME_KEY_2:
            return pbkdf2Async(password, salt, PBKDF2_ITERATIONS, 32, PBKDF2_DIGEST);
        default:
            return Promise.reject(new Error(`Unknown encryption scheme ${scheme}`));
    }
}

// How many derivations run on the libuv thread pool at once. The pool is shared with dns.lookup()
// and file system calls, and at startup every account with a salt of its own asks for a derivation
// of about 40 ms, so an unbounded burst would hold up the IMAP connects waiting behind it
const MAX_PARALLEL_DERIVATIONS = 2;
let runningDerivations = 0;
const waitingDerivations = [];

async function limitedDerivation(fn) {
    if (runningDerivations >= MAX_PARALLEL_DERIVATIONS) {
        await new Promise(resolve => waitingDerivations.push(resolve));
    }
    runningDerivations++;
    try {
        return await fn();
    } finally {
        runningDerivations--;
        const next = waitingDerivations.shift();
        if (next) {
            next();
        }
    }
}

// The asynchronous counterpart of getKeyFromPassword(), sharing its cache
async function getKeyFromPasswordAsync(scheme, password, salt) {
    const cacheKey = cacheKeyFor(scheme, password, salt);
    let cachedKey = saltCache(cacheKey, salt);
    if (cachedKey) {
        return cachedKey;
    }
    if (!PENDING_KEYS.has(cacheKey)) {
        PENDING_KEYS.set(
            cacheKey,
            limitedDerivation(() => deriveKeyAsync(scheme, password, salt))
                .then(key => saltCache(cacheKey, salt, key))
                .finally(() => PENDING_KEYS.delete(cacheKey))
        );
    }
    return await PENDING_KEYS.get(cacheKey);
}

/**
 * Parses a stored value for decryption
 * @returns {{cleartext: string}|{decryptData: Object}} The value itself when there is nothing to decrypt
 */
function parseForDecrypt(encryptedData, secret) {
    const raw = (encryptedData || '').toString('utf-8');

    if (!secret || !raw) {
        return { cleartext: raw };
    }

    const decryptData = parseEncryptedData(raw);
    if (![WD_ENCRYPTION_SCHEME_KEY_1, WD_ENCRYPTION_SCHEME_KEY_2].includes(decryptData.format)) {
        // cleartext, or a format this version does not know, which is treated as cleartext
        return { cleartext: raw };
    }

    return { decryptData };
}

function decryptError(E) {
    let err = new Error('Failed to decrypt data. ' + E.message);
    err.responseCode = 500;
    err.code = 'InternalConfigError';
    return err;
}

function checkDecryptData(decryptData) {
    assert.strictEqual(decryptData.authTag.length, 16, 'Invalid auth tag length');
    assert.strictEqual(decryptData.iv.length, IV_LENGTH, 'Invalid iv length');
    assert.strictEqual(decryptData.salt.length, SALT_LENGTH, 'Invalid salt length');
    assert.strictEqual(decryptData.cipher, WD_CIPHER_1, 'Unsupported cipher');
}

function decipherWith(decryptData, key) {
    const decipher = crypto.createDecipheriv(decryptData.cipher, key, decryptData.iv, {
        authTagLength: decryptData.authTag.length
    });
    decipher.setAuthTag(decryptData.authTag);

    // try to decipher
    return Buffer.concat([decipher.update(decryptData.data), decipher.final()]).toString('utf-8');
}

function decrypt(encryptedData, secret) {
    const { cleartext, decryptData } = parseForDecrypt(encryptedData, secret);
    if (!decryptData) {
        return cleartext;
    }

    try {
        checkDecryptData(decryptData);
        // convert password to 32B key, the way the value's scheme says
        const key = getKeyFromPassword(decryptData.format, secret, decryptData.salt);
        return decipherWith(decryptData, key);
    } catch (E) {
        throw decryptError(E);
    }
}

/**
 * decrypt() with the key derivation run on the libuv thread pool. A key that is not cached costs a
 * 600000 iteration PBKDF2 (or a scrypt for wd01), about 40 ms that the synchronous decrypt() spends
 * with the event loop blocked. A worker loading many accounts at startup whose values each carry
 * their own salt (written before the salt became per process) used to do that once per account,
 * one after another. Same result and errors as decrypt(), same key cache
 * @param {string|Buffer} encryptedData
 * @param {string} secret
 * @returns {Promise<string>}
 */
async function decryptAsync(encryptedData, secret) {
    const { cleartext, decryptData } = parseForDecrypt(encryptedData, secret);
    if (!decryptData) {
        return cleartext;
    }

    try {
        checkDecryptData(decryptData);
        const key = await getKeyFromPasswordAsync(decryptData.format, secret, decryptData.salt);
        return decipherWith(decryptData, key);
    } catch (E) {
        throw decryptError(E);
    }
}

function encrypt(cleartext, secret) {
    if (!secret || !cleartext) {
        return cleartext;
    }

    // Never encrypted twice. A stored value that did not decrypt (the secret was rotated without
    // `emailengine encrypt`) is read back as the ciphertext it is, and a partial update of the
    // record used to write it back encrypted again, which put the only recoverable copy of the
    // credential beyond the rotation CLI. Ciphertext is left as it is, so a later run with the
    // right secret still opens it
    if (typeof cleartext === 'string' && parseEncryptedData(cleartext).format !== 'cleartext') {
        return cleartext;
    }

    // Random per value: GCM is only secure while no IV repeats under a key, and every value this
    // process writes shares one key
    const iv = crypto.randomBytes(IV_LENGTH);
    const salt = getProcessSalt();

    const format = WD_ENCRYPTION_SCHEME;
    const algo = WD_CIPHER;

    // Cached after the first write of this process
    const key = getKeyFromPassword(format, secret, salt);

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

/**
 * Tells whether a stored value is encrypted under the scheme encrypt() writes today. A value under
 * an older scheme still decrypts, and is what `emailengine encrypt` rewrites
 *
 * @param {String} value - The stored value
 * @returns {Boolean}
 */
function isCurrentScheme(value) {
    return parseEncryptedData(value).format === WD_ENCRYPTION_SCHEME;
}

/**
 * The value `emailengine encrypt` stores for one it found: unchanged when it is already under the
 * current secret and scheme, otherwise decrypted with whichever of the secrets reads it and written
 * again with the current secret, or as cleartext when there is none. Throws when no secret reads
 * it, so nothing is overwritten with a guess
 *
 * @param {String} value - The stored value
 * @param {String[]} decryptSecrets - Secrets the value may have been written with
 * @param {String} [encryptSecret] - The secret to write with; nothing removes the encryption
 * @returns {String} The value to store
 */
function reencrypt(value, decryptSecrets, encryptSecret) {
    if (parseEncryptedData(value).format === 'cleartext') {
        return encryptSecret ? encrypt(value, encryptSecret) : value;
    }

    let lastErr;
    // the current secret first: a value already under it is the common case
    for (const secret of new Set([encryptSecret, ...decryptSecrets].filter(Boolean))) {
        let decrypted;
        try {
            decrypted = decrypt(value, secret);
        } catch (err) {
            lastErr = err;
            continue;
        }
        if (parseEncryptedData(decrypted).format !== 'cleartext') {
            // a scheme decrypt() does not know comes back as it was
            break;
        }
        if (secret === encryptSecret && isCurrentScheme(value)) {
            return value;
        }
        return encryptSecret ? encrypt(decrypted, encryptSecret) : decrypted;
    }
    throw lastErr || new Error('Could not decrypt encrypted value');
}

module.exports = {
    encrypt,
    decrypt,
    decryptAsync,
    encryptField,
    decryptField,
    parseEncryptedData,
    isCurrentScheme,
    reencrypt,
    PBKDF2_ITERATIONS,
    PBKDF2_DIGEST
};
