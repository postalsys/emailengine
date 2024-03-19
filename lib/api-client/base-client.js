'use strict';

const crypto = require('crypto');
const logger = require('../logger');
const { REDIS_PREFIX } = require('../consts');

class BaseClient {
    constructor(account, options) {
        this.account = account;

        this.options = options || {};

        this.cid = this.getRandomId();

        this.runIndex = this.options.runIndex;

        this.accountObject = this.options.accountObject;
        this.accountLogger = this.options.accountLogger;
        this.redis = this.options.redis;
        this.logger = this.options.logger || logger;

        this.secret = this.options.secret;

        this.subconnections = [];
    }

    // stub methods

    async init() {
        return null;
    }

    async delete() {
        return null;
    }

    async resume() {
        return null;
    }

    async subconnections() {
        return [];
    }

    async getQuota() {
        return false;
    }

    getRandomId() {
        let rid = BigInt('0x' + crypto.randomBytes(13).toString('hex')).toString(36);
        if (rid.length < 20) {
            rid = '0'.repeat(20 - rid.length) + rid;
        } else if (rid.length > 20) {
            rid = rid.substring(0, 20);
        }
        return rid;
    }

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getMailboxListKey() {
        return `${REDIS_PREFIX}ial:${this.account}`;
    }

    getMailboxHashKey() {
        return `${REDIS_PREFIX}iah:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${this.account}:g`;
    }

    getLoggedAccountsKey() {
        return `${REDIS_PREFIX}iaz:logged`;
    }

    currentState() {
        return 'connected';
    }
}

module.exports = { BaseClient };
