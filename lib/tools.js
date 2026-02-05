/* eslint no-bitwise: 0 */

// NB! This file is processed by gettext parser and can not use newer syntax like ?.

'use strict';

const msgpack = require('msgpack5')();
const enumMessageFlags = require('./enum-message-flags');
const Joi = require('joi');
const he = require('he');
const packageData = require('../package.json');
const settings = require('./settings');
const { brotliDecompress } = require('zlib');
const util = require('util');
const brotliDecompressAsync = util.promisify(brotliDecompress);
const { createPublicKey, createVerify, randomBytes, createHmac } = require('crypto');
const logger = require('./logger');
const Boom = require('@hapi/boom');
const { ImapFlow } = require('imapflow');
const nodemailer = require('nodemailer');
const { parentPort } = require('worker_threads');
const punycode = require('punycode.js');
const { PassThrough } = require('stream');
const socks = require('socks');
const os = require('os');
const Fs = require('fs');
const fs = Fs.promises;
const pathlib = require('path');
const { randomUUID: uuid } = require('crypto');
const mimeTypes = require('nodemailer/lib/mime-funcs/mime-types');
const { v3: murmurhash } = require('murmurhash');
const { compare: compareVersions, validate: validateVersion } = require('compare-versions');
const {
    REDIS_PREFIX,
    TLS_DEFAULTS,
    URL_FETCH_TIMEOUT,
    MAX_FORM_TTL,
    FETCH_RETRY_INTERVAL,
    FETCH_RETRY_EXPONENTIAL,
    FETCH_RETRY_MAX,
    URL_FETCH_RETRY_MAX
} = require('./consts');
const bullmqPackage = require('bullmq/package.json');

// Network utilities - imported for internal use only
const { getLocalAddress } = require('./utils/network');

const { fetch: fetchCmd, Agent, RetryAgent } = require('undici');

const fetchAgent = new Agent({
    strictContentLength: false,
    connectTimeout: Math.min(30000, URL_FETCH_TIMEOUT), // up to 30s for connection
    headersTimeout: URL_FETCH_TIMEOUT, // Full timeout (90s)
    bodyTimeout: URL_FETCH_TIMEOUT // Full timeout (90s)
});

const retryAgent = new RetryAgent(fetchAgent, {
    maxRetries: URL_FETCH_RETRY_MAX,
    methods: ['GET', 'PUT', 'HEAD', 'OPTIONS', 'DELETE', 'POST'],
    statusCodes: [429] // do not retry 5xx errors
});

class LRUCache extends Map {
    constructor(maxSize = 1000) {
        super();
        this.maxSize = maxSize;
    }

    set(key, value) {
        if (this.size >= this.maxSize) {
            const firstKey = this.keys().next().value;
            this.delete(firstKey);
        }
        super.set(key, value);
    }
}

const regexCache = new LRUCache(1000);

function formatTokenError(provider, tokenRequest) {
    let parts = [`Token request failed for ${provider}`];
    if (tokenRequest) {
        let detail = `${tokenRequest.grant || 'unknown'}, HTTP ${tokenRequest.status || '?'}`;
        parts[0] += ` (${detail})`;
        if (tokenRequest.response) {
            let resp = tokenRequest.response;
            let errorParts = [resp.error, resp.error_description].filter(Boolean);
            if (errorParts.length) {
                parts.push(errorParts.join(' - '));
            }
        }
    }
    return parts.join(': ');
}

module.exports = {
    /**
     * Helper function to set specific bit in a buffer
     * @param {Buffer} buffer Buffer to edit
     * @param {Number} bytePos Which byte in buffer to edit
     * @param {Number} bit Which bit to update
     * @param {Boolean} value If true, then sets bit, if false, then clears it
     * @returns {Boolean} If true then bit was updated
     */
    setBit(buffer, bytePos, bit, value) {
        bytePos = Number(bytePos) || 0;
        if (bytePos < 0 || bytePos >= buffer.length) {
            return false;
        }

        if (!value) {
            buffer[bytePos] &= ~(1 << bit);
        } else {
            buffer[bytePos] |= 1 << bit;
        }

        return true;
    },

    /**
     * Helper function to get specific bit from a buffer
     * @param {Buffer} buffer Buffer to check for
     * @param {Number} bytePos Which byte in buffer to check
     * @param {Number} bit Which bit to check
     * @returns {Boolean} If true then bit was set, otherwise bit was not set
     */
    readBit(buffer, bytePos, bit) {
        return !!((buffer[bytePos] >> bit) % 2);
    },

    /**
     * Parses stored message entry
     * @param {Buffer} buffer Stored message entry
     * @ @returns {Object} Message entry object
     */
    unserialize(buffer) {
        // < [4B (UInt32LE) UID] [1B ENUM_FLAGS] [8B (BigUInt64LE) MODSEQ] [nB META (msgpack) [msgid, [flags], [labels]] ] >

        if (buffer.length === 1) {
            switch (buffer.toString()) {
                case 'D': {
                    return { deleted: true };
                }
                case 'N': {
                    return { placeholder: true };
                }
            }
            return {};
        }

        let uid = buffer.readUInt32LE(0);
        let modseq = buffer.readBigUInt64LE(5);

        let formatted = {
            uid,
            flags: new Set()
        };

        if (modseq) {
            formatted.modseq = modseq;
        }

        enumMessageFlags.forEach((flag, i) => {
            if (module.exports.readBit(buffer, 4, i)) {
                formatted.flags.add(flag);
            }
        });

        if (buffer.length > 4 + 1 + 8) {
            let extra = msgpack.decode(buffer.slice(4 + 1 + 8));
            if (Array.isArray(extra)) {
                let emailId = extra[0];
                if (emailId) {
                    formatted.emailId = emailId;
                }

                if (Array.isArray(extra[1])) {
                    extra[1].forEach(flag => {
                        formatted.flags.add(flag);
                    });
                }

                if (Array.isArray(extra[2])) {
                    formatted.labels = new Set(extra[2]);
                }
            }
        }

        return formatted;
    },

    /**
     * Generates message entry for storage
     * @param {Object} messageData Message entry object
     * @ @returns {Buffer} Serialized message entry for storage
     */
    serialize(messageData) {
        let buf = Buffer.alloc(4 + 1 + 8);
        buf.writeUInt32LE(messageData.uid, 0);

        let extra = [
            messageData.emailId || null, //emailId (if exists)
            null, // extra flags not in the default flag set
            null // labels if Gmail All data
        ];

        for (let flag of messageData.flags) {
            let enumFlag = enumMessageFlags.indexOf(flag);
            if (enumFlag >= 0) {
                module.exports.setBit(buf, 4, enumFlag, true);
            } else {
                if (!extra[1]) {
                    extra[1] = [];
                }
                extra[1].push(flag);
            }
        }

        if (messageData.labels && messageData.labels.size) {
            extra[2] = Array.from(messageData.labels);
        }

        if (messageData.modseq) {
            buf.writeBigUInt64LE(messageData.modseq, 5);
        }

        return Buffer.concat([buf, msgpack.encode(extra)]);
    },

    /**
     * Compares two message objects to see if there are any changes
     * @param {*} storedMessageEntry
     * @param {*} messageData
     * @returns {Object | Boolean} Changes or false
     */
    compareExisting(storedMessageEntry, messageData, keys) {
        const changes = {};
        let hasChanges = false;

        // detect deleted flags
        if (!keys || keys.includes('flags')) {
            let hasFlagChanges = false;

            for (let flag of storedMessageEntry.flags.values()) {
                if (!messageData.flags.has(flag)) {
                    if (!changes.flags) {
                        changes.flags = {};
                    }
                    if (!changes.flags.deleted) {
                        changes.flags.deleted = [];
                    }
                    changes.flags.deleted.push(flag);
                    hasChanges = true;
                    hasFlagChanges = true;
                }
            }

            // detect added flags
            for (let flag of messageData.flags.values()) {
                if (!storedMessageEntry.flags.has(flag)) {
                    if (!changes.flags) {
                        changes.flags = {};
                    }
                    if (!changes.flags.added) {
                        changes.flags.added = [];
                    }
                    changes.flags.added.push(flag);
                    hasChanges = true;
                    hasFlagChanges = true;
                }
            }

            if (hasFlagChanges) {
                changes.flags.value = Array.from(messageData.flags);
            }
        }

        if (!keys || keys.includes('labels')) {
            let hasLabelChanges = false;

            if (storedMessageEntry.labels || messageData.labels) {
                if (storedMessageEntry.labels) {
                    // detect deleted labels
                    for (let flag of storedMessageEntry.labels.values()) {
                        if (!messageData.labels || !messageData.labels.has(flag)) {
                            if (!changes.labels) {
                                changes.labels = {};
                            }
                            if (!changes.labels.deleted) {
                                changes.labels.deleted = [];
                            }
                            changes.labels.deleted.push(flag);
                            hasChanges = true;
                            hasLabelChanges = true;
                        }
                    }
                }
                if (messageData.labels) {
                    // detect added labels
                    for (let flag of messageData.labels.values()) {
                        if (!storedMessageEntry.labels || !storedMessageEntry.labels.has(flag)) {
                            if (!changes.labels) {
                                changes.labels = {};
                            }
                            if (!changes.labels.added) {
                                changes.labels.added = [];
                            }
                            changes.labels.added.push(flag);
                            hasChanges = true;
                            hasLabelChanges = true;
                        }
                    }
                }

                if (hasLabelChanges) {
                    changes.labels.value = messageData.labels ? Array.from(messageData.labels) : [];
                }
            }
        }

        return hasChanges ? changes : false;
    },

    normalizePath(path, separator) {
        if (separator) {
            return path.replace(new RegExp(`^INBOX($|${module.exports.escapeRegExp(separator)})`, 'i'), n => n.toUpperCase());
        }

        if (/^INBOX$/i.test(path)) {
            return 'INBOX';
        }

        return path;
    },

    async resolveCredentials(account, proto) {
        let authServer = await settings.get('authServer');
        if (!authServer) {
            let err = new Error('Authentication server requested but not set');
            throw err;
        }

        let headers = {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        };

        let parsed = new URL(authServer);
        let username, password;

        if (parsed.username) {
            username = he.decode(parsed.username);
            parsed.username = '';
        }

        if (parsed.password) {
            password = he.decode(parsed.password);
            parsed.password = '';
        }

        if (username || password) {
            headers.Authorization = `Basic ${Buffer.from(he.encode(username || '') + ':' + he.encode(password || '')).toString('base64')}`;
        }

        parsed.searchParams.set('account', account);
        parsed.searchParams.set('proto', proto);

        let authResponse = await fetchCmd(parsed.toString(), { method: 'GET', headers, dispatcher: retryAgent });
        if (!authResponse.ok) {
            throw new Error(`Invalid response: ${authResponse.status} ${authResponse.statusText}`);
        }

        let authData = await authResponse.json();
        if (!authData) {
            throw new Error('Failed resolving credentials for ' + account);
        }

        const schema = Joi.object({
            user: Joi.string().max(256).required(),
            pass: Joi.string()
                .allow('')
                .max(256)
                .when('accessToken', {
                    is: Joi.exist().not(false, null),
                    then: Joi.optional().valid(false, null),
                    otherwise: Joi.required()
                }),
            accessToken: Joi.string().max(4 * 4096)
        });

        const { error, value } = schema.validate(authData, {
            abortEarly: false,
            stripUnknown: true,
            convert: true
        });

        if (error) {
            throw error;
        }

        return value;
    },

    getWorkerCount(processCount) {
        if (/^\s*cpus\s*$/i.test(processCount)) {
            processCount = os.cpus().length;
        }

        if (typeof processCount !== 'number' && !isNaN(processCount)) {
            processCount = Number(processCount);
        }

        if (isNaN(processCount)) {
            processCount = 0;
        }

        return processCount;
    },

    getDuration(val, opts = {}) {
        val = (val || '').toString().replace(/^([\d.]+)\s*([smhdy][a-z]*)$/i, (o, num, m) => {
            if (!num || isNaN(num)) {
                return false;
            }

            num = Number(num);
            if (!num) {
                return num;
            }

            let unit = m.charAt(0).toLowerCase();
            if (unit === 'm' && m.charAt(1).toLowerCase() === 's') {
                unit = 'ms';
            }

            switch (unit) {
                case 'ms':
                    // keep as is
                    break;
                case 's':
                    num = num * 1000;
                    break;
                case 'm':
                    if (/^mo/i.test(m)) {
                        // month
                        num = num * (30 * 24 * 3600 * 1000);
                    } else {
                        // minute
                        num = num * (60 * 1000);
                    }
                    break;
                case 'h':
                    num = num * (3600 * 1000);
                    break;
                case 'd':
                    num = num * (24 * 3600 * 1000);
                    break;
                case 'y':
                    num = num * (365 * 24 * 3600 * 1000);
                    break;
            }

            return Math.round(num);
        });

        if (isNaN(val)) {
            return val;
        }

        if (opts.seconds) {
            return Math.ceil(Number(val) / 1000);
        }

        return Number(val);
    },

    getByteSize(val) {
        if (typeof val === 'number') {
            return val;
        }

        val = (val || '').toString().replace(/^([\d.]+)\s*([kMGTP])B?$/i, (o, num, m) => {
            if (!num || isNaN(num)) {
                return false;
            }

            num = Number(num);
            if (!num) {
                return num;
            }

            switch (m.toUpperCase()) {
                case 'K':
                    num = num * 1024;
                    break;
                case 'M':
                    num = num * 1024 * 1024;
                    break;
                case 'G':
                    num = num * 1024 * 1024 * 1024;
                    break;
                case 'T':
                    num = num * 1024 * 1024 * 1024 * 1024;
                    break;
                case 'P':
                    num = num * 1024 * 1024 * 1024 * 1024 * 1024;
                    break;
            }

            return Math.round(num);
        });

        if (isNaN(val)) {
            return val;
        }

        return Number(val);
    },

    formatByteSize(val) {
        if (isNaN(val)) {
            return val;
        }
        val = Number(val);

        let types = new Set([
            ['PB', 1024 * 1024 * 1024 * 1024 * 1024],
            ['TB', 1024 * 1024 * 1024 * 1024],
            ['GB', 1024 * 1024 * 1024],
            ['MB', 1024 * 1024],
            ['kB', 1024]
        ]);

        for (let [[type, nr]] of types.entries()) {
            if (val % nr === 0) {
                return `${Math.round(val / nr)}${type}`;
            }
        }

        return val;
    },

    formatAccountListingResponse(entry) {
        if (Array.isArray(entry)) {
            let obj = {};
            for (let i = 0; i < entry.length; i += 2) {
                obj[entry[i]] = entry[i + 1];
            }
            return obj;
        }
        // return default
        return entry;
    },

    getDateBuckets(seconds) {
        let now = new Date();
        let startTime = new Date(now.getTime() - seconds * 1000);

        let bucketKeys = [];

        // find out all the date buckets we need to check for
        let endDateStr = `${now
            .toISOString()
            .substr(0, 10)
            .replace(/[^0-9]+/g, '')}`;
        let dateStr = '00000000';
        let hashTime = startTime;

        let startTimeStr = `${startTime
            .toISOString()
            // bucket includes 1 minute
            .substring(0, 16)
            .replace(/[^0-9]+/g, '')}`;

        while (dateStr < endDateStr) {
            dateStr = `${hashTime
                .toISOString()
                .substr(0, 10)
                .replace(/[^0-9]+/g, '')}`;
            bucketKeys.push(dateStr);
            hashTime = new Date(hashTime.getTime() + 24 * 3600 * 1000);
        }

        return { bucketKeys, startTimeStr };
    },

    async getCounterValues(redis, seconds) {
        seconds = Number(seconds) || 3600;

        const { bucketKeys: hashKeys, startTimeStr } = module.exports.getDateBuckets(seconds);

        // list potential counter keys
        let statUpdateKeys = await redis.smembers(`${REDIS_PREFIX}stats:keys`);

        let req = redis.multi();
        let rIndex = [];

        for (let statUpdateKey of statUpdateKeys) {
            // load stats for this key
            for (let dateStr of hashKeys) {
                req = req.hgetall(`${REDIS_PREFIX}stats:${statUpdateKey}:${dateStr}`);
                rIndex.push(statUpdateKey);
            }
        }

        let res = await req.exec();

        let counters = {};

        for (let i = 0; i < res.length; i++) {
            let value = res[i];
            let statUpdateKey = rIndex[i];

            if (value[0]) {
                // error found
            } else {
                Object.keys(value[1] || {}).forEach(key => {
                    if (key >= startTimeStr) {
                        if (!counters[statUpdateKey]) {
                            counters[statUpdateKey] = 0;
                        }
                        counters[statUpdateKey] += Number(value[1][key]) || 0;
                    }
                });
            }
        }

        return counters;
    },

    escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
    },

    getRendezvousScore(key, shardId) {
        return murmurhash(`${(shardId || '').toString()}\x00${key}`);
    },

    selectRendezvousNode(key, workers) {
        return workers.map(worker => ({ worker, score: module.exports.getRendezvousScore(key, worker.threadId) })).sort((a, b) => b.score - a.score)[0].worker;
    },

    selectRendezvousAddress(key, addresses) {
        let scoredAddresses = addresses.map(address => ({ address, score: module.exports.getRendezvousScore(key, address) })).sort((a, b) => b.score - a.score);
        return scoredAddresses[0].address;
    },

    getBoolean(value) {
        if (typeof value === 'boolean') {
            return value;
        }

        if (typeof value === 'string') {
            value = value.trim();
        }

        if (typeof value === 'string' && !isNaN(value) && /^[0-9]+$/.test(value)) {
            value = Number(value);
        }

        if (typeof value === 'number') {
            return !!value;
        }

        if (typeof value === 'string') {
            return /^(y|true)/i.test(value);
        }

        return false; // ????
    },

    async checkLicense(license) {
        let verifyKeys = [
            // main-key-1
            `-----BEGIN PUBLIC KEY-----
MFIwEAYHKoZIzj0CAQYFK4EEAAMDPgAEAaBbeChuyKlNp0MFi4nnRelWA6H/JHWr
ZdCXj2+HK4j0W0yzPN8VX0P7ox+1YgXNegBNchjVuu6xWSKE
-----END PUBLIC KEY-----`,
            // trial-key-1
            `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV3QUiYsp13nD9suD1/ZkEXnuMoSg
8ZRXhDSmZQgW92fmNTsPs3tB6fQ3eAqO4JECE5Y2sI2EX/+Gm8JcErRhDg==
-----END PUBLIC KEY-----
`
        ].map(key => createPublicKey(key));

        let encodedLicense;
        if (!/\n/.test(license.toString().trim())) {
            encodedLicense = Buffer.from(license.toString().trim(), 'base64url');
        } else {
            encodedLicense = Buffer.from(
                license
                    .toString()
                    .split(/\r?\n/)
                    .map(line => line.trim())
                    .filter(line => line && !/[^a-z0-9+/=]/i.test(line))
                    .join(''),
                'base64'
            );
        }

        let signedLicense = await brotliDecompressAsync(encodedLicense);

        let { l: licenseRaw, s: signature } = msgpack.decode(signedLicense);

        let signedBy;
        for (let verifyKey of verifyKeys) {
            try {
                const verify = createVerify('SHA256');
                verify.write(licenseRaw);
                verify.end();
                const isSigned = verify.verify(verifyKey, signature);
                if (isSigned) {
                    signedBy = verifyKey;
                    break;
                }
            } catch (err) {
                // failed to verify, check another key if possible
            }
        }

        if (!signedBy) {
            let err = new Error('Failed to verify signature');
            err.code = 'ELicenseValidation';
            throw err;
        }

        const rawLicenseData = msgpackDecode(licenseRaw);

        const licenseData = {
            application: rawLicenseData.a,
            key: rawLicenseData.k.toString('hex'),
            licensedTo: rawLicenseData.n,
            hostname: rawLicenseData.h,
            created: new Date(rawLicenseData.c).toISOString(),
            trial: rawLicenseData.t
        };

        if (rawLicenseData.l) {
            licenseData.lt = true;
        }

        if (rawLicenseData.e) {
            if (Date.now() > rawLicenseData.e) {
                let err = new Error('License expired');
                err.code = 'ELicenseExpired';
                throw err;
            }

            licenseData.expires = new Date(rawLicenseData.e).toISOString();
        }

        if (rawLicenseData.t) {
            licenseData.trial = true;
        }

        return licenseData;
    },

    async flash(redis, request, value) {
        if (!request || !request.state || !request.state.crumb) {
            return;
        }

        let rkey = `${REDIS_PREFIX}fl:${request.state.crumb}`;
        try {
            if (value) {
                await redis.multi().lpush(rkey, JSON.stringify(value)).expire(rkey, 3600).exec();
            } else {
                let res = await redis.multi().lrange(rkey, 0, -1).del(rkey).exec();
                if (!res || !res[0] || !res[0][1]) {
                    return false;
                }
                return res[0][1].map(entry => JSON.parse(entry));
            }
        } catch (err) {
            // ignore
        }
    },

    async failAction(request, h, err) {
        try {
            let details = (err.details || []).map(detail => ({ message: detail.message, key: detail.context.key }));

            delete err._original;

            logger.error({
                msg: 'Request failed',
                method: request.method,
                route: request.route.path,
                statusCode: request.response && request.response.statusCode,
                err
            });

            let message = request.app.gt.gettext('Invalid input');
            let error = Boom.boomify(new Error(message), { statusCode: 400 });
            error.output.payload.fields = details;

            throw error;
        } catch (E) {
            request.logger.error({ err: E });
            throw E;
        }
    },

    async verifyAccountInfo(redis, accountData, logger) {
        let response = {};

        let proxyUrl = await settings.get('proxyUrl');
        let proxyEnabled = await settings.get('proxyEnabled');

        let verifyPromises = [];

        if (accountData.imap) {
            verifyPromises.push(
                (async () => {
                    try {
                        let imapConfig = Object.assign(
                            {
                                verifyOnly: true,
                                includeMailboxes: accountData.mailboxes,

                                greetingTimeout: 90 * 1000,

                                clientInfo: {
                                    name: (await settings.get('imapClientName')) || packageData.name,
                                    version: (await settings.get('imapClientVersion')) || packageData.version,
                                    vendor: (await settings.get('imapClientVendor')) || (packageData.author && packageData.author.name) || packageData.author,
                                    'support-url':
                                        (await settings.get('imapClientSupportUrl')) || (packageData.bugs && packageData.bugs.url) || packageData.bugs
                                }
                            },
                            accountData.imap
                        );

                        // set up proxy if needed
                        if (accountData.proxy) {
                            imapConfig.proxy = accountData.proxy;
                        } else if (proxyEnabled && proxyUrl && !imapConfig.proxy) {
                            imapConfig.proxy = proxyUrl;
                        }

                        if (logger) {
                            imapConfig.logger = logger;
                        }

                        if (!imapConfig.tls) {
                            imapConfig.tls = {};
                        }

                        for (let key of Object.keys(TLS_DEFAULTS)) {
                            if (!(key in imapConfig.tls)) {
                                imapConfig.tls[key] = TLS_DEFAULTS[key];
                            }
                        }

                        const ignoreMailCertErrors = await settings.get('ignoreMailCertErrors');
                        if (ignoreMailCertErrors && imapConfig && imapConfig.tls && imapConfig.tls.rejectUnauthorized !== false) {
                            imapConfig.tls = imapConfig.tls || {};
                            imapConfig.tls.rejectUnauthorized = false;
                        }

                        let imapClient = new ImapFlow(imapConfig);

                        let mailboxes = await new Promise((resolve, reject) => {
                            imapClient.on('error', err => {
                                imapClient.close();
                                reject(err);
                            });
                            imapClient
                                .connect()
                                .then(() => resolve(imapClient._mailboxList))
                                .catch(reject);
                        });

                        response.imap = {
                            success: !!imapClient.authenticated
                        };

                        if (accountData.mailboxes && mailboxes && mailboxes.length) {
                            // format mailbox listing
                            let mailboxList = [];
                            for (let entry of mailboxes) {
                                let mailbox = {};
                                Object.keys(entry).forEach(key => {
                                    if (['path', 'specialUse', 'name', 'listed', 'subscribed', 'delimiter', 'specialUseSource', 'noInferiors'].includes(key)) {
                                        mailbox[key] = entry[key];
                                    }
                                });
                                if (mailbox.delimiter && mailbox.path.indexOf(mailbox.delimiter) >= 0) {
                                    mailbox.parentPath = mailbox.path.substr(0, mailbox.path.lastIndexOf(mailbox.delimiter));
                                }
                                mailboxList.push(mailbox);
                            }
                            response.mailboxes = mailboxList;
                        }
                    } catch (err) {
                        logger.error({ msg: 'Account verification failed', err });
                        response.imap = {
                            success: false,
                            error: err.message,
                            code: err.serverResponseCode || err.code,
                            statusCode: err.statusCode,
                            responseText: err.responseText
                        };
                    }
                })()
            );
        }

        if (accountData.smtp) {
            verifyPromises.push(
                (async () => {
                    try {
                        let { localAddress: address, name } = await getLocalAddress(redis, 'smtp', 'test');

                        let smtpLogger = {};
                        let smtpConfig = Object.assign(
                            {
                                name,
                                localAddress: address,
                                transactionLog: true,
                                logger: smtpLogger
                            },
                            accountData.smtp
                        );

                        if (!smtpConfig.tls) {
                            smtpConfig.tls = {};
                        }
                        for (let key of Object.keys(TLS_DEFAULTS)) {
                            if (!(key in smtpConfig.tls)) {
                                smtpConfig.tls[key] = TLS_DEFAULTS[key];
                            }
                        }

                        for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
                            smtpLogger[level] = (data, message, ...args) => {
                                if (args && args.length) {
                                    message = util.format(message, ...args);
                                }
                                data.msg = message;
                                data.sub = 'nodemailer';
                                if (typeof logger[level] === 'function') {
                                    logger[level](data);
                                } else {
                                    logger.debug(data);
                                }
                            };
                        }

                        // set up proxy if needed
                        if (accountData.proxy) {
                            smtpConfig.proxy = accountData.proxy;
                        } else if (proxyEnabled && proxyUrl && !smtpConfig.proxy) {
                            smtpConfig.proxy = proxyUrl;
                        }

                        if (accountData.smtpEhloName) {
                            smtpConfig.name = accountData.smtpEhloName;
                        }

                        smtpConfig.forceAuth = true;

                        const ignoreMailCertErrors = await settings.get('ignoreMailCertErrors');
                        if (ignoreMailCertErrors && smtpConfig && smtpConfig.tls && smtpConfig.tls.rejectUnauthorized !== false) {
                            smtpConfig.tls = smtpConfig.tls || {};
                            smtpConfig.tls.rejectUnauthorized = false;
                        }

                        if (smtpConfig.auth && smtpConfig.auth.accessToken) {
                            smtpConfig.auth.type = 'OAuth2';
                        }

                        const smtpClient = nodemailer.createTransport(smtpConfig);
                        smtpClient.set('proxy_socks_module', socks);
                        response.smtp = {
                            success: await smtpClient.verify()
                        };
                    } catch (err) {
                        response.smtp = {
                            success: false,
                            error: err.message,
                            code: err.code,
                            statusCode: err.statusCode,
                            responseText: err.response
                        };
                    }
                })()
            );
        }

        await Promise.all(verifyPromises);

        return response;
    },

    async runPrechecks(redis) {
        let keyName = Buffer.from([108, 105, 99, 101, 110, 115, 101]).toString();
        let content = (await redis.hget(`${REDIS_PREFIX}settings`, keyName)) || '';
        let assertedBy;

        if (content) {
            let rootList = [
                Buffer.from(
                    '2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d464977454159484b6f5a497a6a3043415159464b34454541414d44506741454161426265436875794b6c4e70304d4669346e6e52656c574136482f4a4857720a5a6443586a322b484b346a305730797a504e3856583050376f782b315967584e6567424e63686a567575367857534b450a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d',
                    'hex'
                ).toString(),
                Buffer.from(
                    '2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a30444151634451674145563351556959737031336e4439737544312f5a6b45586e754d6f53670a385a52586844536d5a5167573932666d4e54735073337442366651336541714f344a45434535593273493245582f2b476d384a634572526844673d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a',
                    'hex'
                ).toString()
            ].map(key => createPublicKey(key));

            let encodedContent;
            if (!/\n/.test(content.toString().trim())) {
                encodedContent = Buffer.from(content.toString().trim(), 'base64url');
            } else {
                encodedContent = Buffer.from(
                    content
                        .toString()
                        .split(/\r?\n/)
                        .map(line => line.trim())
                        .filter(line => line && !/[^a-z0-9+/=]/i.test(line))
                        .join(''),
                    'base64'
                );
            }

            let signedContent = await brotliDecompressAsync(encodedContent);
            let { l: contentRaw, s: signature } = msgpack.decode(signedContent);
            for (let rootItem of rootList) {
                try {
                    const verify = createVerify('SHA256');
                    verify.write(contentRaw);
                    verify.end();
                    const isSigned = verify.verify(rootItem, signature);
                    if (isSigned) {
                        assertedBy = rootItem;
                        break;
                    }
                } catch (err) {
                    // ignore
                }
            }
        }

        if (!assertedBy) {
            let err = new Error(Buffer.from('4661696c656420746f20766572696679207369676e6174757265', 'hex').toString());
            err.code = Buffer.from('45436f6e74656e7456616c69646174696f6e', 'hex').toString();
            throw err;
        }
    },

    isEmail(str) {
        const schema = Joi.object({
            email: Joi.string().email().required()
        });

        const { error, value } = schema.validate(
            { email: str },
            {
                abortEarly: false,
                stripUnknown: true,
                convert: true
            }
        );

        if (error) {
            return false;
        }

        return value.email;
    },

    async emitChangeEvent(logger, account, type, key, payload) {
        try {
            parentPort.postMessage({
                cmd: 'change',
                account,
                type,
                key,
                payload: payload || null
            });
        } catch (err) {
            logger.error({ msg: 'Failed to post state change to parent', err });
        }
    },

    getLogs(redis, account) {
        let logKey = `${REDIS_PREFIX}iam:${account}:g`;
        let passThrough = new PassThrough();

        passThrough.headers = {
            'content-type': 'text/plain',
            'content-disposition': `attachment; filename=${JSON.stringify(`logs.${account}.txt`)}`
        };

        redis
            .lrangeBuffer(logKey, 0, -1)
            .then(rows => {
                if (!rows || !Array.isArray(rows) || !rows.length) {
                    return passThrough.end(`No logs found for ${account}\n`);
                }
                let processNext = () => {
                    if (!rows.length) {
                        return passThrough.end();
                    }

                    let row = rows.shift();
                    let entry;
                    try {
                        entry = msgpack.decode(row);
                    } catch (err) {
                        entry = { error: err.stack };
                    }

                    if (entry) {
                        if (!passThrough.write(JSON.stringify(entry) + '\n')) {
                            return passThrough.once('drain', processNext);
                        }
                    }

                    setImmediate(processNext);
                };

                processNext();
            })
            .catch(err => {
                passThrough.end(`\nFailed to process logs\n${err.stack}\n`);
            });

        return passThrough;
    },

    flattenObjectKeys(obj) {
        let result = {};
        let seen = new WeakSet();
        let walk = (prefix, c) => {
            if (!c || typeof c !== 'object') {
                return;
            }
            for (let key of Object.keys(c)) {
                let value = c[key];

                if (value && typeof value === 'object' && !Array.isArray(value) && Object.prototype.toString.call(value) !== '[object Date]') {
                    if (seen.has(value)) {
                        // recursive
                        continue;
                    }
                    seen.add(value);
                    walk([].concat(prefix || []).concat(key), value);
                } else {
                    let printKey = []
                        .concat(prefix || [])
                        .concat(key)
                        .join('_');
                    result[printKey] = value;
                }
            }
        };
        walk(false, obj);
        return result;
    },

    async getRedisStats(redis) {
        let info = [await redis.info(), await redis.info('commandstats')].join('\n');

        let formatValue = val => {
            if (/^[-+]?\d+(.\d+)?$/.test(val) && !/^0\d+/.test(val)) {
                return Number(val);
            }

            switch (val) {
                case 'yes':
                    return true;
                case 'no':
                    return false;
            }

            if (val.indexOf('=') >= 0) {
                // object with keys
                val = Object.fromEntries(val.split(',').map(e => [e.substr(0, e.indexOf('=')), formatValue(e.substr(e.indexOf('=') + 1))]));
            }

            return val;
        };

        let infoObj = Object.fromEntries(
            info
                .split(/\r?\n/)
                .filter(l => l.indexOf(':') >= 0)
                .map(l => [l.substr(0, l.indexOf(':')), formatValue(l.substr(l.indexOf(':') + 1))])
        );

        let cmdstat_total = {
            calls: 0,
            usec: 0,
            rejected_calls: 15,
            failed_calls: 0
        };

        Object.keys(infoObj).forEach(key => {
            if (key.indexOf('cmdstat_') === 0) {
                Object.keys(infoObj[key]).forEach(cKey => {
                    if (typeof cmdstat_total[cKey] === 'number') {
                        cmdstat_total[cKey] += infoObj[key][cKey];
                    }
                });
            }
        });

        infoObj.cmdstat_total = cmdstat_total;
        try {
            let slowlogLen = await redis.slowlog('len');
            infoObj.slowlog_length = formatValue(slowlogLen);
        } catch (err) {
            // not supported by Upstash
            infoObj.slowlog_length = 0;
        }

        return infoObj;
    },

    async getStats(redis, call, seconds) {
        const structuredMetrics = await call({ cmd: 'structuredMetrics' });

        let counters = await module.exports.getCounterValues(redis, seconds);

        let redisVersion;
        let softwareDetails;
        let redisSoftware;
        let redisCluster = false;

        try {
            let redisInfo = await module.exports.getRedisStats(redis);

            if (!redisInfo || typeof redisInfo.redis_version !== 'string') {
                throw new Error('Failed to fetch Redis INFO');
            }
            redisVersion = redisInfo.redis_version;

            if (redisInfo.cluster_enabled && Number(redisInfo.cluster_enabled) && !isNaN(redisInfo.cluster_enabled) && redisInfo.cluster_enabled > 0) {
                redisCluster = true;
            }

            // Detect Dragonfly
            if (typeof redisInfo.dragonfly_version === 'string') {
                softwareDetails = `Dragonfly v${redisInfo.dragonfly_version.replace(/^[^\d]*/, '')}`;
                redisSoftware = 'dragonfly';
            }

            // Detect KeyDB
            if (typeof redisInfo.mvcc_depth === 'number') {
                softwareDetails = `KeyDB`;
                redisSoftware = 'keydb';
            }

            // Detect Upstash
            if (typeof redisInfo.upstash_version === 'string') {
                softwareDetails = `Upstash Redis v${redisInfo.upstash_version.replace(/^[^\d]*/, '')}`;
                redisSoftware = 'upstash';
            }

            // Detect Memurai
            if (typeof redisInfo.memurai_version === 'string') {
                softwareDetails = `${redisInfo.memurai_edition || 'Memurai'} v${redisInfo.memurai_version.replace(/^[^\d]*/, '')}`;
                redisSoftware = 'memurai';
            }

            // Detect ElastiCache
            if (/Amazon ElastiCache/i.test(redisInfo.os)) {
                softwareDetails = `Amazon ElastiCache`;
                redisSoftware = 'elasticache';
            }

            // Detect MemoryDB
            if (/Amazon MemoryDB/i.test(redisInfo.os)) {
                softwareDetails = `Amazon MemoryDB`;
                redisSoftware = 'memorydb';
            }
        } catch (err) {
            logger.error({ msg: 'Failed to get stats', err });
            redisVersion = err.message;
        }

        let queues = {};
        for (let queue of ['notify', 'submit', 'documents']) {
            try {
                const [resActive, resDelayed, resWaiting, resPaused, resMeta] = await redis
                    .multi()
                    .llen(`${REDIS_PREFIX}bull:${queue}:active`)
                    .zcard(`${REDIS_PREFIX}bull:${queue}:delayed`)
                    .llen(`${REDIS_PREFIX}bull:${queue}:wait`)
                    .llen(`${REDIS_PREFIX}bull:${queue}:paused`)
                    .hget(`${REDIS_PREFIX}bull:${queue}:meta`, 'paused')
                    .exec();
                if (resActive[0] || resDelayed[0] || resWaiting[0] || resPaused[0] || resMeta[0]) {
                    // counting failed
                    logger.error({ msg: 'Failed to count queue length', queue, active: resActive, delayed: resDelayed, waiting: resWaiting });
                    return false;
                }
                queues[queue] = {
                    active: Number(resActive[1]) || 0,
                    delayed: Number(resDelayed[1]) || 0,
                    waiting: Number(resWaiting[1]) || 0,
                    paused: Number(resPaused[1]) || 0,
                    isPaused: !!Number(resMeta[1]) || false
                };
                queues[queue].total = queues[queue].active + queues[queue].delayed + queues[queue].waiting + queues[queue].paused;
            } catch (err) {
                logger.error({ msg: 'Failed to count queue length', queue, err });
            }
        }

        let stats = Object.assign(
            {
                version: packageData.version,
                license: packageData.license,
                accounts: await redis.scard(`${REDIS_PREFIX}ia:accounts`),
                node: process.versions.node,
                redis: `${redisVersion}${softwareDetails ? ` (${softwareDetails})` : ''}`,
                redisSoftware,
                redisCluster,
                imapflow: ImapFlow.version || 'please upgrade',
                bullmq: bullmqPackage.version,
                arch: process.arch,
                counters,
                queues
            },
            structuredMetrics
        );

        try {
            // version info file might not exist
            let versionFile = await fs.readFile(pathlib.join(__dirname, '..', 'version-info.json'), 'utf-8');
            if (versionFile) {
                let versionData = JSON.parse(versionFile);
                stats.build = versionData;
            }
        } catch (err) {
            // ignore
        }

        return stats;
    },

    async fetchReleaseInfo() {
        const releaseUrl = `https://api.github.com/repos/postalsys/emailengine/releases/latest`;

        let headers = {
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
        };

        let releaseResponse = await fetchCmd(releaseUrl, { method: 'GET', headers, dispatcher: retryAgent });
        if (!releaseResponse.ok) {
            let err = new Error(`Failed loading release data`);
            err.response = {
                status: releaseResponse.status
            };
            try {
                err.response.data = await releaseResponse.json();
            } catch (err) {
                //ignore
            }
            throw err;
        }

        let releaseData = await releaseResponse.json();
        if (!releaseData) {
            throw new Error('Failed loading release data');
        }

        return releaseData;
    },

    async checkForUpgrade() {
        let releaseData;
        try {
            releaseData = await module.exports.fetchReleaseInfo();
        } catch (err) {
            return { current: packageData.version, available: false, canUpgrade: false };
        }

        let releaseVersion = (releaseData.tag_name || '').toString().replace(/^v/, '');
        if (!validateVersion(releaseVersion)) {
            return { current: packageData.version, available: false, canUpgrade: false };
        }

        if (compareVersions(releaseVersion, packageData.version, '>')) {
            return { current: packageData.version, available: releaseVersion, canUpgrade: true };
        }

        return { current: packageData.version, available: releaseVersion, canUpgrade: false };
    },

    formatPartialSecretKey(secretKey) {
        return secretKey.replace(/^(.{8}).*$/, `$1... (${secretKey.length}B)`);
    },

    validUidValidity(value) {
        if (typeof value === 'bigint' || typeof value === 'number') {
            return true;
        }

        if (isNaN(value)) {
            return false;
        }

        return !!value;
    },

    mergeObjects(destination, source) {
        for (let propKey of Object.keys(source)) {
            let sourceVal = source[propKey];

            if (typeof destination[propKey] === 'undefined') {
                destination[propKey] = sourceVal;
                continue;
            }

            if (destination[propKey] && sourceVal && typeof destination[propKey] === 'object' && typeof sourceVal === 'object') {
                module.exports.mergeObjects(destination[propKey], sourceVal);
                continue;
            }

            // new value set, do not change it
        }
    },

    async getServiceSecret() {
        let serviceSecret = await settings.get('serviceSecret');
        if (!serviceSecret) {
            serviceSecret = randomBytes(16).toString('hex');
            await settings.set('serviceSecret', serviceSecret);
        }
        return serviceSecret;
    },

    async getSignedFormData(opts) {
        const serviceSecret = await module.exports.getServiceSecret();
        return module.exports.getSignedFormDataSync(serviceSecret, opts);
    },

    filterEmptyObjectValues(obj) {
        let res = {};
        for (let key of Object.keys(obj)) {
            if (obj[key]) {
                res[key] = obj[key];
            }
        }
        return res;
    },

    getSignedFormDataSync(serviceSecret, opts, asIs) {
        opts = opts || {};

        let data = Buffer.from(
            JSON.stringify(
                asIs
                    ? opts
                    : module.exports.filterEmptyObjectValues({
                          account: opts.account,
                          name: opts.name,
                          email: opts.email,
                          syncFrom: (opts.syncFrom && opts.syncFrom.toISOString()) || null,
                          notifyFrom: (opts.notifyFrom && opts.notifyFrom.toISOString()) || null,
                          subconnections: opts.subconnections && opts.subconnections.length ? opts.subconnections : null,
                          redirectUrl: opts.redirectUrl,
                          delegated: opts.delegated,
                          path: opts.path,
                          n: opts.n,
                          t: opts.t
                      })
            )
        );

        let signature;

        let hmac = createHmac('sha256', serviceSecret);
        hmac.update(data);
        signature = hmac.digest('base64url');

        return { data: data.toString('base64url'), signature };
    },

    async parseSignedFormData(redis, payload, gt) {
        let data = Buffer.from(payload.data, 'base64url').toString();
        let serviceSecret = await settings.get('serviceSecret');
        if (serviceSecret) {
            let hmac = createHmac('sha256', serviceSecret);
            hmac.update(data);
            if (hmac.digest('base64url') !== payload.sig) {
                let error = Boom.boomify(new Error(gt.gettext('Signature validation failed')), { statusCode: 403 });
                throw error;
            }
        }

        data = JSON.parse(data);

        if (data.n && data.t) {
            if (data.t < Date.now() - (MAX_FORM_TTL - 60 * 1000)) {
                let error = Boom.boomify(new Error(gt.gettext('Invalid or expired account setup URL')), { statusCode: 403 });
                throw error;
            }
            const nonceSeen = await redis.exists(`${REDIS_PREFIX}account:form:${data.n}`);
            if (nonceSeen) {
                let error = Boom.boomify(new Error(gt.gettext('Invalid or expired account setup URL')), { statusCode: 403 });
                throw error;
            }
        }

        return data;
    },

    async setLicense(licenseData, licenseFile) {
        await settings.setLicense(licenseData, licenseFile);
    },

    async download(stream) {
        return new Promise((resolve, reject) => {
            let chunks = [];
            let chunklen = 0;
            stream.on('error', err => reject(err));
            stream.on('readable', () => {
                let chunk;
                while ((chunk = stream.read()) !== null) {
                    if (typeof chunk === 'string') {
                        chunk = Buffer.from(chunk);
                    }
                    if (!chunk || !Buffer.isBuffer(chunk)) {
                        // what's that?
                        return;
                    }
                    chunks.push(chunk);
                    chunklen += chunk.length;
                }
            });
            stream.on('end', () => {
                resolve(Buffer.concat(chunks, chunklen));
            });
        });
    },

    async getServiceHostname(providedHostname) {
        let hostname;
        if (providedHostname) {
            hostname = providedHostname;
        } else {
            let serviceUrl = (await settings.get('serviceUrl')) || null;
            hostname = serviceUrl ? (new URL(serviceUrl).hostname || '').toString().toLowerCase().trim() : os.hostname();
        }

        if (hostname) {
            try {
                hostname = punycode.toASCII(hostname);
            } catch (err) {
                // ignore
            }
        }

        return hostname;
    },

    unpackUIDRangeForSearch(uid) {
        uid = (uid || '').toString();
        let parts = uid
            .split(',')
            .map(u => u.trim())
            .filter(u => u);

        let queryEntries = [];

        for (let part of parts) {
            if (!isNaN(part) && Number(part)) {
                queryEntries.push(Number(part));
            } else if (part.indexOf(':') >= 0) {
                let entry = {};
                let [a, b] = part.split(':');
                if (!isNaN(a) && Number(a)) {
                    entry.gte = Number(a);
                }
                if (!isNaN(b) && Number(b)) {
                    entry.lte = Number(b);
                }
                if (Object.keys(entry).length) {
                    queryEntries.push(entry);
                }
            }
        }

        return queryEntries;
    },

    comparePattern(pattern, input) {
        let regex;
        if (regexCache.has(pattern)) {
            regex = regexCache.get(pattern);
        }

        if (!regex) {
            let escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
            regex = new RegExp(`^${escaped}$`);
            regexCache.set(pattern, regex);
        }

        return regex.test(input);
    },

    matcher(patterns, input) {
        for (let pattern of patterns) {
            if (module.exports.comparePattern(pattern, input)) {
                return true;
            }
        }

        return false;
    },

    hasEnvValue(key) {
        return key in process.env || `${key}_FILE` in process.env;
    },

    readEnvValue(key) {
        if (key in process.env) {
            return process.env[key];
        }

        if (typeof process.env[`${key}_FILE`] === 'string' && process.env[`${key}_FILE`]) {
            try {
                // try to load from file
                process.env[key] = Fs.readFileSync(process.env[`${key}_FILE`], 'utf-8').replace(/\r?\n/g, '\n').trim();
                logger.trace({ msg: 'Loaded environment value from file', key, file: process.env[`${key}_FILE`] });
            } catch (err) {
                logger.fatal({ msg: 'Failed to load environment value from file', key, file: process.env[`${key}_FILE`], err });
                process.env[key] = '';
            }
            return process.env[key];
        }
    },

    convertDataUrisToAttachments(data) {
        if (data.html) {
            let cidCounter = 0;
            let html = data.html.replace(/(<img\b[^>]* src\s*=[\s"']*)(data:([^;]+);[^"'>\s]+)/gi, (match, prefix, dataUri, mimeType) => {
                let cid = `${uuid()}@emailengine`;
                if (!data.attachments) {
                    data.attachments = [];
                }
                data.attachments.push({
                    path: dataUri,
                    cid,
                    filename: 'image-' + ++cidCounter + '.' + mimeTypes.detectExtension(mimeType)
                });
                return prefix + 'cid:' + cid;
            });

            if (cidCounter) {
                data.html = html;
            }
        }
    },

    threadStats: {
        startTime: Date.now(),

        usage() {
            const currentTimestamp = Date.now();

            // Use process.memoryUsage() instead of v8.getHeapStatistics()
            // to avoid potential SEGV issues in worker threads
            const memUsage = process.memoryUsage();

            return {
                uptime: currentTimestamp - this.startTime,
                heapUsed: memUsage.heapUsed,
                heapTotal: memUsage.heapTotal,
                external: memUsage.external,
                rss: memUsage.rss,
                arrayBuffers: memUsage.arrayBuffers || 0
            };
        }
    },

    structuredClone: typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data)),

    loadTlsConfig(ref, envPrefix) {
        if (!ref || typeof ref !== 'object') {
            return false;
        }

        for (let key of ['ca', 'cert', 'key', 'dhparam']) {
            let path = `${key}Path`;
            if (ref[path] && typeof ref[path] === 'string') {
                // read value from file
                try {
                    ref[key] = Fs.readFileSync(ref[path], 'utf-8').replace(/\r?\n/g, '\n').trim();
                    logger.trace({ msg: 'Loaded environment TLS value from file', path, file: ref[path] });
                    delete ref[path];
                } catch (err) {
                    logger.fatal({ msg: 'Failed to load TLS value from file', path, file: ref[path], err });
                    ref[key] = null;
                }
            }
        }

        // string keys for TLS
        for (let key of ['ca', 'cert', 'ciphers', 'ecdhCurve', 'key', 'dhparam', 'minVersion', 'maxVersion', 'passphrase']) {
            let envKey = `${envPrefix}${key.replace(/[A-Z]/g, c => `_${c}`).toUpperCase()}`;
            if (module.exports.hasEnvValue(envKey)) {
                ref[key] = module.exports.readEnvValue(envKey);
            }
        }

        // Boolean keys for TLS
        for (let key of ['rejectUnauthorized', 'requestCert']) {
            if (ref[key] && typeof ref[key] !== 'boolean') {
                ref[key] = module.exports.getBoolean(ref[key]);
            }

            let envKey = `${envPrefix}${key.replace(/[A-Z]/g, c => `_${c}`).toUpperCase()}`;
            if (module.exports.hasEnvValue(envKey)) {
                ref[key] = module.exports.getBoolean(module.exports.readEnvValue(envKey));
            }
        }
    },

    genBaseBoundary() {
        return [
            Buffer.from(Date.now().toString(16), 'hex').toString('base64url'),
            Buffer.from(`ee@${packageData.version}`).toString('base64url'),
            randomBytes(8).toString('base64url')
        ].join('_');
    },

    calculateFetchBackoff: attempt => Math.min(FETCH_RETRY_MAX, FETCH_RETRY_INTERVAL * FETCH_RETRY_EXPONENTIAL ** attempt),

    async resolveDelegatedAccount(redis, account) {
        let redirect = 0;

        let seenAccounts = new Set();
        let hopsAllowed = 20;

        while (redirect++ < hopsAllowed) {
            let oauth2DataStr = await redis.hget(`${REDIS_PREFIX}iad:${account}`, 'oauth2');
            if (!oauth2DataStr) {
                let error = new Error(`Missing account data for delegated account "${account}"`);
                throw error;
            }
            let oauth2Data;
            try {
                oauth2Data = JSON.parse(oauth2DataStr);
            } catch (err) {
                let error = new Error(`Invalid account data for delegated account "${account}"`);
                throw error;
            }

            if (oauth2Data && oauth2Data.auth && oauth2Data.auth.delegatedUser && oauth2Data.auth.delegatedAccount) {
                if (seenAccounts.has(account)) {
                    // loop detected
                    let error = new Error('Delegation looping detected');
                    throw error;
                }
                seenAccounts.add(account);
                account = oauth2Data.auth.delegatedAccount;
                continue;
            }

            break;
        }

        if (redirect >= hopsAllowed) {
            let error = new Error('Too many delegation hops');
            throw error;
        }

        return account;
    },

    prepareUrl(url, baseUrl, queryParams) {
        let { pathname: baseUrlPathname } = new URL(baseUrl);
        // Ensure pathname ends with trailing slash for proper path concatenation
        if (!baseUrlPathname.endsWith('/')) {
            baseUrlPathname += '/';
        }

        const urlObj = new URL(baseUrlPathname + url.replace(/^\//, ''), baseUrl);

        for (let param of Object.keys(queryParams || {})) {
            let value = queryParams[param];
            if (typeof value === 'undefined' || value === null) {
                continue;
            }
            urlObj.searchParams.append(param, value);
        }

        return urlObj.href;
    },

    fetchAgent,
    retryAgent,

    LRUCache,

    normalizeHashKeys,

    formatTokenError
};

function msgpackDecode(buf) {
    const RK = `
iqW2M2Hp2cesXicj
UjYeEzGrAI0ykwqs
0uZ57ewCA71u2PXK
KTm+Lqf7H7h81+2F
k6502/PIpNfA03Ir
5XC/Hyx/3SxT7hZW
fHbz1HHkQvWNaJXg
k+8vv5QtRaTr4O3q
1XF46qGcYyanlbxB
aa6xwLPc8AxwqxzN
6i40Ie4phMyqUQzi
0AqJ69kff8wj4z9X
KVmA5bw9zJMuMR0G
MfvFQbraGODiT19b
GyqiLzoM2WBGkPLF
SiMSUx5ZzP+KaUNg
3b3QGMXmxs9PUgco
s7YWddnO3q0D3Kqc
BZuj6C0wk6AflB86
Oa4rS6X5XHZenDBh
K48CLaXb35Wyf8ud
6JVHv+g7kUXqgLct
fbc/2bFTnDtwN5Kc
vVTQRmss6oa+o3Bj
pbe+b1BjM97Voc21
m++c/pjABuMM+rTc
9n+AzH3APP7Qzq+C
oPpCZh28fyCPv2TZ
t0xCngRgaIZRuD3T
dBb0Tc1IggSKY8dD
exRqrporGRl2rjBf
r+p1xHpDF4Ct0jfn
QeunHH85jTFcsR7e
kBFI6x6tfC8K1C8E
uMDwyq9Y+GFLdSZF
Qmt72SAp9U458OaT
PlpLZjr4BL0pohCK
aj9NNZwr9Q4xzJvU
fS/JLszz84j1ag5o
8Me3v4Gs+ToXrx7m
X8CeIMqigilchDt6
8eBpFKOmpq2kLEQF
NxQ1lmMn6iPIStjg
o2I9/Op/fQs4bsif
yl8bUlV5Ru9PlpNW
sak1JCNvKyYLfYyj
Jp6Yf75xjccdFJUO
WO98DhF4vrdYWoNN
0GY3Y69nPMhxmQ0z
G8IkXqjVdLZwBK/I
+AZoia19FAsARLE/
dmHXmtUSriMvBTCJ
FKQbQ1hVZXra8Wcq
4fe7zF1Wd8UdaWu4
8RCLotSALncqTCtE
z2nO73rl3nRMvf6r
Ws0yTT8UnJNTFWY7
QYZcQD2niO2kGJ9N
Wp6z04Yho9uWIObC
aPkKbjEuTbUCplG7
8ORR3ntJhKaosv0/
IbZu0b/MWBxfqGte
TYJ9FfWyzUlZbQaB
bg5xk8Y5UaJ5MiNo
V+7QViQcrIxNEjZO
XMvnP1RmJhcT4Au7
RYuvlgtYgLRqpaFS
PZJL9AdMO0zGOlKs
ipR+vBSSJsONTZHG
mz3HC3/NOiZmUgoY
X9ijCxDcuKTTzQP7
SxrPmcwdIRLwJQI4
87hi6i4YfdDxDmxW
4V+M2+at3SSF+Ahd
qDB8JZU2XDkNE4yi
D5TBGMWLMcrFz6Su
BBZw9cpGXGovER70
2fYp+CSZiIa6tpaI
wsBE9o15ikqnkCHw
LFFrh69mbvG6I953
gb0c28e4bDbaxj5W
GInvRxkFTnPN97g2
zGGN/NlynQ4GvZ3e
MQ87qSEBNQJip6GS
Vqm95KM44kL4+7qd
uSY0M+yfff4Op/HP
h7Squx/sKZNkDat0
elb9jWFuO3UHnphx
//m57pmYUuiv84pZ
wInk+UccjElRBe8v
4kywfQ5AFdYxn//+
VytcPvNrABw/JS+e
czn1ie17ikAXC0fx
bp3iCgOwvQyncj1n
U5YAhY30g8d7nDpu
JF+qOcL5dIiYUija
hAso3Wv1mlMIHmOQ
8JXBCoY6JVlEMu/Q
xV1YkQ3cgw0EpJZ8
AP9o7PxYTzhDxdZa
qurB4y++jCni0Bpf
x/shDcuK2iB4gef2
ONdADmVw/ZXhNBl8
HdjLwB+Gg6OPAC2G
ePrAvrzNl3snvOmZ
8wCKpX9Md98W3+x1
f4dfpceJ+d8AWqvr
StJiRRn+nx8nVxjn
pjB2LZf7wdpcwA6O
/fev2uWbhZQrBTRU
sE/AvEajiziKRRuo
WAIVvOY3vf+Mie6w
dqSdBG8PMMURCCa0
PaqEsvhCelUyvGjO
vYJujGyIBP4WpSBg
r/CVn8qB2xdyVXCg
vPHQ3BYeEr+9DSlW
vIwyKmyMuykMUPeA
RTIy3POEF2gZADpU
N6P36E+eiwOGfjQ3
ukA5k4XrI0U/kl7t
RSvpJCGXq7lbwx3S
h/TUqvLGXjB8N8xu
u61uYKx5DLO9eNR7
vWuuhT9ely8AUX2F
nQNwPlZ+tyx24XVo
cyp1GKV4Cl+eC8G/
Q1y/TzbtUQCqnotR
59Q2qOkuyTLzQDhd
vR2igTteHNS2f1CQ
ele2bJB9ZuHl0sw7
C8MNYeCjyQjdvxim
aZBE0lOjBe4XuK5E
SJVPHpfUX3kpFpLi
J5hGmNpIvL7cc4Jn
3arFOanxm/RO8U5c
VNRO9yqTV90pZSsm
fvZjf0oEWxQhZR1+
U5rSIV2iOlITDu0c
5pQtz9Su+AzjBkV1
AW6pdfk8U1/EXPdY
Q/6B3a679QVyRrsE
1xyU3RkTVo/iQd3J
`
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l);
    const val = msgpack.decode(buf);
    if (RK.includes(val.k.toString('base64'))) {
        val.e = 1;
    }
    return val;
}

async function executeBatch(redis, hashKey, deleteOps, renameOps) {
    if (deleteOps.length === 0 && renameOps.length === 0) {
        return;
    }

    const pipeline = redis.pipeline();

    // Delete duplicates
    for (const field of deleteOps) {
        pipeline.hdel(hashKey, field);
    }

    // Rename fields (delete old, set new)
    for (const { oldField, newField, value } of renameOps) {
        pipeline.hdel(hashKey, oldField);
        pipeline.hset(hashKey, newField, value);
    }

    // Execute all operations
    await pipeline.exec();
}

async function normalizeHashKeys(redis, hashKey, options = {}) {
    const { batchSize = 100, scanCount = 100, normalizeField = field => (field || '').toLowerCase() } = options;

    const summary = {
        totalKeys: 0,
        normalizedKeys: 0,
        droppedDuplicates: 0,
        errors: []
    };

    // Track normalized keys we've seen to detect duplicates across scan iterations
    const seenNormalizedKeys = new Set();

    // Batch operations for pipeline
    const deleteOperations = [];
    const renameOperations = [];

    try {
        let cursor = '0';

        do {
            // Scan a batch of fields
            const [newCursor, fields] = await redis.hscan(hashKey, cursor, 'COUNT', scanCount);
            cursor = newCursor;

            // Process fields in pairs (field, value)
            for (let i = 0; i < fields.length; i += 2) {
                const field = fields[i];
                const value = fields[i + 1];

                if (/^__/.test(field)) {
                    // ignore special keys
                    continue;
                }

                summary.totalKeys++;

                const normalizedField = normalizeField(field);

                // Skip if already normalized
                if (field === normalizedField) {
                    seenNormalizedKeys.add(normalizedField);
                    continue;
                }

                // Check if normalized version already exists
                if (seenNormalizedKeys.has(normalizedField)) {
                    // Schedule for deletion (duplicate)
                    deleteOperations.push(field);
                    summary.droppedDuplicates++;
                } else {
                    // Check if normalized key exists in Redis
                    const exists = await redis.hexists(hashKey, normalizedField);

                    if (exists) {
                        // Normalized key exists, drop the unnormalized one
                        deleteOperations.push(field);
                        summary.droppedDuplicates++;
                    } else {
                        // Schedule for renaming
                        renameOperations.push({
                            oldField: field,
                            newField: normalizedField,
                            value
                        });
                        seenNormalizedKeys.add(normalizedField);
                        summary.normalizedKeys++;
                    }
                }

                // Execute operations in batches to avoid memory buildup
                if (deleteOperations.length + renameOperations.length >= batchSize) {
                    await executeBatch(redis, hashKey, deleteOperations, renameOperations);
                    deleteOperations.length = 0;
                    renameOperations.length = 0;
                }
            }
        } while (cursor !== '0');

        // Execute any remaining operations
        if (deleteOperations.length > 0 || renameOperations.length > 0) {
            await executeBatch(redis, hashKey, deleteOperations, renameOperations);
        }
    } catch (error) {
        summary.errors.push(error.message);
    }

    return summary;
}
