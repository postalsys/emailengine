'use strict';

// The account hash codec: how Account.serializeAccountData() stores a field in Redis and how
// Account.unserializeAccountData() reads it back, for every field that is not kept as the plain
// string it is stored as. Both look the field up here and fall back to the plain string.
//
// Every entry is called as (accountObject, key, accountData, result), decoders with skipDecrypt as
// a fifth argument, and writes into `result` itself, or writes nothing when the field stores or
// reads as nothing. Writing in place rather than returning a value keeps the output keys in the
// order of the input keys, which the webhookErrorFlag reset in encodeWebhooks() depends on. An
// encoder is never called for a field holding undefined: serializeAccountData() skips it.

const { encrypt, parseEncryptedData } = require('../encrypt');

// Subkeys of the connection objects that hold dates
const CONNECTION_DATE_KEYS = ['created', 'expires', 'generated'];

// Credentials inside a connection object, looked up in its `auth` first (imap, smtp) and then
// beside it (the OAuth2 tokens)
const CONNECTION_SECRET_KEYS = ['pass', 'accessToken', 'refreshToken'];

function isValidDateObject(value) {
    return value && typeof value === 'object' && typeof value.toISOString === 'function' && value.toString() !== 'Invalid Date';
}

function isStringable(value) {
    return typeof value !== 'undefined' && value !== null && typeof value.toString === 'function';
}

/**
 * Parses a stored JSON value. A value that does not parse is logged and, like a stored `null`,
 * reads as undefined: the field is then left out of the account.
 */
function parseStoredJson(accountObject, key, stored, ownerAccount) {
    let value;
    try {
        value = JSON.parse(stored);
    } catch (err) {
        accountObject.logUnserializeFailure('Failed to parse input from Redis', key, stored, ownerAccount, err);
        return undefined;
    }
    return value === null ? undefined : value;
}

// Sets the parsed stored JSON value as the field, unless it is null or does not parse. Returns the
// value, so a decoder can go on to convert parts of it in place
function setStoredJson(accountObject, key, stored, accountData, result) {
    const value = parseStoredJson(accountObject, key, stored, accountData.account);
    if (value !== undefined) {
        result[key] = value;
    }
    return value;
}

function logStringifyFailure(accountObject, key, err) {
    accountObject.logger.error({ msg: 'Failed to stringify input for Redis', key, account: accountObject.account, err });
}

function decodeDate(accountObject, key, accountData, result) {
    const stored = accountData[key];
    if (!stored) {
        return;
    }
    if (stored === 'null') {
        result[key] = null;
        return;
    }
    const date = new Date(stored);
    if (date.toString() !== 'Invalid Date') {
        result[key] = date;
    }
}

function decodeBool(accountObject, key, accountData, result) {
    const stored = accountData[key];
    if (stored && stored !== 'null') {
        result[key] = stored === 'true';
    }
}

// '' is the cleared marker written by encodeClearable() - report it as unset
function decodeNonEmpty(accountObject, key, accountData, result) {
    if (accountData[key]) {
        result[key] = accountData[key];
    }
}

function decodePath(accountObject, key, accountData, result) {
    const stored = accountData[key];
    if (!stored || !stored.length) {
        return;
    }
    if (stored.length > 1 && (/^"|"$/.test(stored) || /^\[|\]$/.test(stored))) {
        // seems like JSON array or string
        setStoredJson(accountObject, key, stored, accountData, result);
    } else {
        // regular string
        result[key] = stored;
    }
}

function decodeEncrypted(accountObject, key, accountData, result, skipDecrypt) {
    const value = skipDecrypt ? accountData[key] : accountObject.decryptAccountField(key, accountData[key], accountData.account);
    if (typeof value !== 'undefined') {
        result[key] = value;
    }
}

function decodeCustomHeaders(accountObject, key, accountData, result, skipDecrypt) {
    let stored = accountData[key];
    if (skipDecrypt) {
        if (accountObject.secret && parseEncryptedData(stored).format !== 'cleartext') {
            // not read by any caller that skips decryption
            return;
        }
    } else {
        stored = accountObject.decryptAccountField(key, stored, accountData.account);
        if (typeof stored === 'undefined') {
            return;
        }
    }
    setStoredJson(accountObject, key, stored, accountData, result);
}

function decodeJson(accountObject, key, accountData, result) {
    setStoredJson(accountObject, key, accountData[key], accountData, result);
}

function decodeOutlookSubscription(accountObject, key, accountData, result) {
    const value = setStoredJson(accountObject, key, accountData[key], accountData, result);
    if (value === undefined) {
        return;
    }
    if (value.expirationDateTime) {
        let expirationDateTime = new Date(value.expirationDateTime);
        if (expirationDateTime.toString() === 'Invalid Date') {
            expirationDateTime = null;
        }
        value.expirationDateTime = expirationDateTime;
    }
}

// Connection settings and stored states: date subkeys become Date objects, null subkeys are dropped
function decodeConnectionJson(accountObject, key, accountData, result) {
    const value = setStoredJson(accountObject, key, accountData[key], accountData, result);
    if (value === undefined) {
        return;
    }
    for (const subKey of CONNECTION_DATE_KEYS) {
        if (value[subKey]) {
            const dateVal = /^[0-9]+$/.test(value[subKey]) ? Number(value[subKey]) : value[subKey];
            const date = new Date(dateVal);
            if (date.toString() !== 'Invalid Date') {
                value[subKey] = date;
            }
        }
    }
    for (const subKey of Object.keys(value)) {
        if (value[subKey] === null) {
            delete value[subKey];
        }
    }
}

function decodeNumber(accountObject, key, accountData, result) {
    result[key] = Number(accountData[key]) || 0;
}

// The fallback for a field with no decoder: the stored string as it is
function decodePlain(accountObject, key, accountData, result) {
    result[key] = accountData[key];
}

const FIELD_DECODERS = new Map([
    ['notifyFrom', decodeDate],
    ['lastWatch', decodeDate],
    ['copy', decodeBool],
    ['logs', decodeBool],
    ['expectedEmail', decodeNonEmpty],
    ['path', decodePath],
    ['webhooks', decodeEncrypted],
    ['proxy', decodeEncrypted],
    ['webhooksCustomHeaders', decodeCustomHeaders],
    ['subconnections', decodeJson],
    ['watchResponse', decodeJson],
    ['watchFailure', decodeJson],
    ['outlookSubscription', decodeOutlookSubscription],
    ['imap', decodeConnectionJson],
    ['smtp', decodeConnectionJson],
    ['imapServerInfo', decodeConnectionJson],
    ['smtpServerEhlo', decodeConnectionJson],
    ['oauth2', decodeConnectionJson],
    ['lastErrorState', decodeConnectionJson],
    ['syncError', decodeConnectionJson],
    ['smtpStatus', decodeConnectionJson],
    ['webhookErrorFlag', decodeConnectionJson],
    ['connections', decodeNumber],
    ['listRegistry', decodeNumber],
    ['runIndex', decodeNumber]
]);

function encodeDate(accountObject, key, accountData, result) {
    const value = accountData[key];
    if (value === 'now') {
        result[key] = new Date().toISOString();
    } else if (isValidDateObject(value)) {
        result[key] = value.toISOString();
    } else if (typeof value === 'string') {
        const date = new Date(value);
        if (date.toString() !== 'Invalid Date') {
            result[key] = date.toISOString();
        }
    } else if (value === null) {
        result[key] = 'null';
    }
}

function encodePath(accountObject, key, accountData, result) {
    const value = accountData[key];
    if (value === null || value === '*' || (Array.isArray(value) && (value.length === 0 || (value.length === 1 && value[0] === '*')))) {
        result[key] = '';
        return;
    }
    try {
        result[key] = JSON.stringify(value);
    } catch (err) {
        logStringifyFailure(accountObject, key, err);
    }
}

function encodeCustomHeaders(accountObject, key, accountData, result) {
    try {
        result[key] = accountObject.encryptAccountField(key, JSON.stringify(accountData[key]));
    } catch (err) {
        logStringifyFailure(accountObject, key, err);
    }
}

function encodeProxy(accountObject, key, accountData, result) {
    if (isStringable(accountData[key])) {
        result[key] = accountObject.encryptAccountField(key, accountData[key].toString());
    }
}

function encodeWebhooks(accountObject, key, accountData, result) {
    if (!isStringable(accountData[key])) {
        return;
    }
    const value = accountData[key].toString();
    if (!value) {
        // clear potential error flag
        result.webhookErrorFlag = '{}';
    }
    result[key] = accountObject.encryptAccountField(key, value);
}

function encodeJson(accountObject, key, accountData, result) {
    try {
        result[key] = JSON.stringify(accountData[key]);
    } catch (err) {
        logStringifyFailure(accountObject, key, err);
    }
}

// Stored state the sync clients write as JSON themselves. A string given here is that JSON already
// and is kept as it is; anything else is encoded, so it reads back as the object it was rather than
// as '[object Object]'
function encodeStoredJson(accountObject, key, accountData, result) {
    if (typeof accountData[key] === 'string') {
        result[key] = accountData[key];
        return;
    }
    encodeJson(accountObject, key, accountData, result);
}

function encodeOutlookSubscription(accountObject, key, accountData, result) {
    try {
        const objValue = Object.assign({}, accountData[key]);

        if (typeof objValue.expirationDateTime === 'number' || typeof objValue.expirationDateTime === 'string') {
            objValue.expirationDateTime = new Date(objValue.expirationDateTime);
        }

        if (isValidDateObject(objValue.expirationDateTime)) {
            objValue.expirationDateTime = objValue.expirationDateTime.toISOString();
        } else if (objValue.expirationDateTime) {
            objValue.expirationDateTime = null;
        }

        result[key] = JSON.stringify(objValue);
    } catch (err) {
        logStringifyFailure(accountObject, key, err);
    }
}

// Encrypts the credentials of a connection object copy in place; a value that does not encrypt is
// logged under its own name and stored as it is
function encryptConnectionSecrets(accountObject, connectData) {
    for (const field of CONNECTION_SECRET_KEYS) {
        let holder;
        if (field in connectData.auth) {
            holder = connectData.auth;
        } else if (field in connectData) {
            holder = connectData;
        } else {
            continue;
        }
        try {
            holder[field] = encrypt(holder[field], accountObject.secret);
        } catch (err) {
            accountObject.logger.error({ msg: 'Failed to encrypt value', key: field, account: accountObject.account, err });
        }
    }
}

function encodeConnectionJson(accountObject, key, accountData, result) {
    try {
        // make a deep copy for manipulation
        const connectData = JSON.parse(JSON.stringify(accountData[key]));

        // if possible encrypt passwords
        if (accountObject.secret && connectData.auth) {
            encryptConnectionSecrets(accountObject, connectData);
        }

        for (const subKey of CONNECTION_DATE_KEYS) {
            const date = accountData[key][subKey];
            if (date && typeof date === 'object' && date.toString() !== 'Invalid Date') {
                connectData[subKey] = date.toISOString();
            }
        }

        result[key] = JSON.stringify(connectData);
    } catch (err) {
        logStringifyFailure(accountObject, key, err);
    }
}

function encodeBool(accountObject, key, accountData, result) {
    if (typeof accountData[key] === 'boolean') {
        result[key] = accountData[key].toString();
    } else if (accountData[key] === null) {
        result[key] = '';
    }
}

// Clearable, so it cannot ride the plain string fallback: that drops nulls, and hmset only ever
// adds keys, which would leave an identity pin settable but never removable. Follows the same
// convention as `copy` - null serializes to the empty marker and decodeNonEmpty() treats it as
// unset - rather than adding a per-field delete to persistUpdate.
function encodeClearable(accountObject, key, accountData, result) {
    if (typeof accountData[key] === 'string' || accountData[key] === null) {
        result[key] = accountData[key] || '';
    }
}

const FIELD_ENCODERS = new Map([
    ['notifyFrom', encodeDate],
    ['lastWatch', encodeDate],
    ['path', encodePath],
    ['webhooksCustomHeaders', encodeCustomHeaders],
    ['proxy', encodeProxy],
    ['subconnections', encodeJson],
    ['watchResponse', encodeJson],
    ['watchFailure', encodeJson],
    ['outlookSubscription', encodeOutlookSubscription],
    ['imap', encodeConnectionJson],
    ['smtp', encodeConnectionJson],
    ['oauth2', encodeConnectionJson],
    ['imapServerInfo', encodeStoredJson],
    ['smtpServerEhlo', encodeStoredJson],
    ['lastErrorState', encodeStoredJson],
    ['syncError', encodeStoredJson],
    ['smtpStatus', encodeStoredJson],
    ['webhookErrorFlag', encodeStoredJson],
    ['webhooks', encodeWebhooks],
    ['copy', encodeBool],
    ['logs', encodeBool],
    ['expectedEmail', encodeClearable]
]);

// The plain string fallback for a field with no encoder: null and undefined are not stored, and
// neither is an object with no string form of its own, which would be stored as '[object Object]'
function encodePlain(accountObject, key, accountData, result) {
    const value = accountData[key];
    if (!isStringable(value)) {
        return;
    }
    if (value.toString === Object.prototype.toString) {
        logStringifyFailure(accountObject, key, new TypeError('An object has no plain string form'));
        return;
    }
    result[key] = value.toString();
}

module.exports = { FIELD_DECODERS, FIELD_ENCODERS, decodePlain, encodePlain };
