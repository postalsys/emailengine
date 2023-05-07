'use strict';

const crypto = require('crypto');
const assert = require('assert');

function parseEncryptedData(encryptedData) {
    encryptedData = (encryptedData || '').toString();
    if (!encryptedData || encryptedData.charAt(0) !== '$') {
        // cleartext
        return {
            format: 'cleartext',
            data: encryptedData
        };
    }

    let [, format, cipher, authTag, iv, salt, encryptedText] = encryptedData.split('$');
    if (!format || !cipher || !authTag || !iv || !encryptedText) {
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

function getKeyFromPassword(password, salt, keyLen) {
    return crypto.scryptSync(password, salt, keyLen);
}

function decrypt(encryptedData, secret) {
    if (!secret || !encryptedData) {
        return encryptedData;
    }

    const decryptData = parseEncryptedData(encryptedData);

    switch (decryptData.format) {
        case 'cleartext':
            return encryptedData;

        case 'wd01':
            try {
                assert.strictEqual(decryptData.authTag.length, 16, 'Invalid auth tag length');
                assert.strictEqual(decryptData.iv.length, 12, 'Invalid iv length');
                assert.strictEqual(decryptData.salt.length, 16, 'Invalid salt length');

                // convert password to 32B key
                const key = getKeyFromPassword(secret, decryptData.salt, 32);

                const decipher = crypto.createDecipheriv(decryptData.cipher, key, decryptData.iv, { authTagLength: decryptData.authTag.length });
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
            return encryptedData;
        }
    }
}

function encrypt(cleartext, secret) {
    if (!secret || !cleartext) {
        return cleartext;
    }

    const iv = crypto.randomBytes(12);
    const salt = crypto.randomBytes(16);

    const key = getKeyFromPassword(secret, salt, 32);

    const format = 'wd01';
    const algo = 'aes-256-gcm';

    const cipher = crypto.createCipheriv(algo, key, iv, { authTagLength: 16 });
    const encryptedText = Buffer.concat([cipher.update(cleartext), cipher.final()]);

    const authTag = cipher.getAuthTag();

    return ['', format, algo].concat([authTag, iv, salt, encryptedText].map(buf => buf.toString('hex'))).join('$');
}

module.exports = { encrypt, decrypt, parseEncryptedData };
