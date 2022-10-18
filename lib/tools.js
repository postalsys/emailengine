/* eslint no-bitwise: 0 */

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
const { PassThrough } = require('stream');
const socks = require('socks');
const os = require('os');
const Fs = require('fs');
const fs = Fs.promises;
const pathlib = require('path');
const uuid = require('uuid');
const mimeTypes = require('nodemailer/lib/mime-funcs/mime-types');
const { v3: murmurhash } = require('murmurhash');
const { compare: compareVersions, validate: validateVersion } = require('compare-versions');
const { REDIS_PREFIX } = require('./consts');
const ipaddr = require('ipaddr.js');

const nodeFetch = require('node-fetch');
const fetchCmd = global.fetch || nodeFetch;

const regexCache = new Map();

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

        let authResponse = await fetchCmd(parsed.toString(), { method: 'GET', headers });
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

    async getCounterValues(redis, seconds) {
        seconds = Number(seconds) || 3600;

        let now = new Date();
        let startTime = new Date(now.getTime() - seconds * 1000);

        let hashKeys = [];

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
            .substr(0, 16)
            .replace(/[^0-9]+/g, '')}`;

        while (dateStr < endDateStr) {
            dateStr = `${hashTime
                .toISOString()
                .substr(0, 10)
                .replace(/[^0-9]+/g, '')}`;
            hashKeys.push(dateStr);
            hashTime = new Date(hashTime.getTime() + 24 * 3600 * 1000);
        }

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

        const rawLicenseData = msgpack.decode(licenseRaw);

        const licenseData = {
            application: rawLicenseData.a,
            key: rawLicenseData.k.toString('hex'),
            licensedTo: rawLicenseData.n,
            hostname: rawLicenseData.h,
            created: new Date(rawLicenseData.c).toISOString()
        };

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

            let message = 'Invalid input';
            let error = Boom.boomify(new Error(message), { statusCode: 400 });
            error.output.payload.fields = details;

            throw error;
        } catch (E) {
            request.logger.error({ err: E });
            throw E;
        }
    },

    async verifyAccountInfo(accountData) {
        let response = {};

        let proxyUrl = await settings.get('proxyUrl');
        let proxyEnabled = await settings.get('proxyEnabled');

        if (accountData.imap) {
            try {
                let imapConfig = Object.assign(
                    {
                        verifyOnly: true,
                        includeMailboxes: accountData.mailboxes
                    },
                    accountData.imap
                );

                // set up proxy if needed
                if (accountData.proxy) {
                    imapConfig.proxy = accountData.proxy;
                } else if (proxyEnabled && proxyUrl && !imapConfig.proxy) {
                    imapConfig.proxy = proxyUrl;
                }

                let imapClient = new ImapFlow(imapConfig);

                let mailboxes = await new Promise((resolve, reject) => {
                    imapClient.on('error', err => {
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
                            if (['path', 'specialUse', 'name', 'listed', 'subscribed', 'delimiter'].includes(key)) {
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
        }

        if (accountData.smtp) {
            try {
                let smtpLogger = {};
                let smtpConfig = Object.assign(
                    {
                        transactionLog: true,
                        logger: smtpLogger
                    },
                    accountData.smtp
                );

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

                smtpConfig.forceAuth = true;

                let smtpClient = nodemailer.createTransport(smtpConfig);
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
        }

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

        let slowlogLen = await redis.slowlog('len');
        infoObj.slowlog_length = formatValue(slowlogLen);

        return infoObj;
    },

    async getStats(redis, call, seconds) {
        const structuredMetrics = await call({ cmd: 'structuredMetrics' });

        let counters = await module.exports.getCounterValues(redis, seconds);

        let redisVersion;
        try {
            let redisInfo = await module.exports.getRedisStats(redis);
            if (!redisInfo || typeof redisInfo.redis_version !== 'string') {
                throw new Error('Failed to fetch Redis INFO');
            }
            redisVersion = redisInfo.redis_version;
        } catch (err) {
            // ignore
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
                    isPaused: !!Number(resPaused[1]) || false
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
                redis: redisVersion,
                imapflow: ImapFlow.version || 'please upgrade',
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

        let releaseResponse = await fetchCmd(releaseUrl, { method: 'GET', headers });
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

    getSignedFormDataSync(serviceSecret, opts, asIs) {
        opts = opts || {};

        let data = Buffer.from(
            JSON.stringify(
                asIs
                    ? opts
                    : {
                          account: opts.account,
                          name: opts.name,
                          email: opts.email,
                          syncFrom: (opts.syncFrom && opts.syncFrom.toISOString()) || null,
                          redirectUrl: opts.redirectUrl
                      }
            )
        );

        let signature;

        let hmac = createHmac('sha256', serviceSecret);
        hmac.update(data);
        signature = hmac.digest('base64url');

        return { data: data.toString('base64url'), signature };
    },

    async setLicense(licenseData, licenseFile) {
        await settings.setLicense(licenseData, licenseFile);
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
                process.env[key] = Fs.readFileSync(process.env[`${key}_FILE`], 'utf-8').replace(/\r?\n$/, '');
                logger.trace({ msg: 'Loaded environment value from file', key, file: process.env[`${key}_FILE`] });
            } catch (err) {
                logger.error({ msg: 'Failed to load environment value from file', key, file: process.env[`${key}_FILE`], err });
                process.env[key] = '';
            }
            return process.env[key];
        }
    },

    convertDataUrisToAtachments(data) {
        if (data.html) {
            let cidCounter = 0;
            let html = data.html.replace(/(<img\b[^>]* src\s*=[\s"']*)(data:([^;]+);[^"'>\s]+)/gi, (match, prefix, dataUri, mimeType) => {
                let cid = `${uuid.v4()}@emailengine`;
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

    matchIp(ip, addresses) {
        let parsed = ipaddr.parse(ip);
        for (let addr of addresses) {
            try {
                let match;
                if (/\/\d+$/.test(addr)) {
                    match = parsed.match(ipaddr.parseCIDR(addr));
                } else {
                    match = parsed.toNormalizedString() === ipaddr.parse(addr).toNormalizedString();
                }
                if (match) {
                    return true;
                }
            } catch (err) {
                logger.error({ msg: 'Failed to parse IP address', ip, addr, err });
            }
        }

        return false;
    }
};
