'use strict';

const { redis } = require('../../db');
const { REDIS_PREFIX } = require('../../consts');
const logger = require('../../logger').child({
    component: 'google-subscriber'
});
const { oauth2Apps } = require('../../oauth2-apps');

const { normalizeHashKeys } = require('../../tools');

class PubSubInstance {
    constructor(parent, opts) {
        this.parent = parent;
        this.opts = opts || {};
        this.app = opts.app;

        this.stopped = false;
        this.recoveryAttempts = 0;
        this.lastRecoveryAttempt = 0;

        this.checkSchemaVersions()
            .catch(err => {
                logger.error({ msg: 'Failed to process shcema versions', err });
            })
            .finally(() => this.startLoop());
    }

    getPubsubAppKey() {
        return `${REDIS_PREFIX}oapp:pub:${this.app}`;
    }

    startLoop() {
        if (this.stopped) {
            return;
        }
        this.run()
            .then(() => {
                this.startLoop();
            })
            .catch(err => {
                logger.error({ msg: 'Failed to process subscription loop', app: this.app, err });

                oauth2Apps.setMeta(this.app, {
                    pubSubFlag: {
                        message: `Failed to process subscription loop`,
                        description: [err.message, err.reason, err.code].filter(val => val).join('; ')
                    }
                });
                setTimeout(() => this.startLoop(), 3000);
            });
    }

    async checkSchemaVersions() {
        let subscriberApps = await redis.smembers(this.getPubsubAppKey());
        let currentSchemaId = 3;
        for (let subscriberApp of subscriberApps || []) {
            let schemaVersion = Number(await redis.hget(`${REDIS_PREFIX}oapp:h:${subscriberApp}`, '__schemaVersion')) || 0;
            if (schemaVersion < currentSchemaId) {
                // migrate
                try {
                    let normalizationResults = await normalizeHashKeys(redis, `${REDIS_PREFIX}oapp:h:${subscriberApp}`, {
                        batchSize: 50, // Process 50 operations at a time
                        scanCount: 200 // Scan 200 fields per iteration
                    });
                    // normalization passed
                    await redis.hset(`${REDIS_PREFIX}oapp:h:${subscriberApp}`, '__schemaVersion', currentSchemaId.toString(10));

                    logger.info({ msg: 'Normalized hash keys', source: 'google', app: subscriberApp, schemaVersion, currentSchemaId, normalizationResults });
                } catch (err) {
                    logger.error({ msg: 'Failed to normalize hash keys', source: 'google', app: subscriberApp, schemaVersion, currentSchemaId, err });
                }
            }
        }
    }

    async processPulledMessage(messageId, data) {
        logger.info({ msg: 'Processing subscription message', source: 'google', app: this.app, messageId, data });

        let payload;
        try {
            payload = JSON.parse(data);
        } catch (err) {
            logger.error({ msg: 'Failed to process subscription message', source: 'google', app: this.app, messageId, data, err });
            return;
        }

        if (!payload || !payload.emailAddress || !payload.historyId) {
            return;
        }

        let subscriberApps = await redis.smembers(this.getPubsubAppKey());
        let accountIds = new Set();
        for (let subscriberApp of subscriberApps || []) {
            let accountId = await redis.hget(`${REDIS_PREFIX}oapp:h:${subscriberApp}`, payload.emailAddress?.toLowerCase());
            if (accountId) {
                accountIds.add(accountId);
            }
        }

        if (!accountIds.size) {
            logger.info({ msg: 'Failed to match email address with account ID', app: this.app, subscriberApps, messageId, emailAddress: payload.emailAddress });
            return;
        }

        try {
            await this.parent.call({ cmd: 'externalNotify', accounts: Array.from(accountIds), historyId: Number(payload.historyId) || null });
        } catch (err) {
            logger.error({ msg: 'Failed to notify about changes', app: this.app, messageId, emailAddress: payload.emailAddress, err });
        }
    }

    async run() {
        // check if app still exists
        let appExists = await redis.sismember(this.parent.getSubscribersKey(), this.app);
        if (!appExists) {
            logger.info({ msg: 'App data not found anymore, removing subscription instance', app: this.app });
            this.stopped = true;
            this.parent.remove(this.app);
            return;
        }

        // Check if subscription needs initial setup (use cached data first)
        await this.getApp();
        if (!this.appData.pubSubSubscription) {
            // Force refresh to confirm subscription is really missing
            await this.getApp(true);
            if (!this.appData.pubSubSubscription) {
                await this.attemptRecovery('Subscription not configured');
                return; // re-enter pull loop via startLoop
            }
        }

        let accessToken = await this.getAccessToken();
        if (!accessToken) {
            logger.error({ msg: 'Failed to retrieve access token', app: this.app });
            throw new Error('Failed to retrieve access token');
        }

        let pullUrl = `https://pubsub.googleapis.com/v1/${this.appData.pubSubSubscription}:pull`;
        let acknowledgeUrl = `https://pubsub.googleapis.com/v1/${this.appData.pubSubSubscription}:acknowledge`;

        try {
            let start = Date.now();

            let pullRes = await this.client.request(accessToken, pullUrl, 'POST', { returnImmediately: false, maxMessages: 100 });
            if (this.stopped) {
                // ignore if stopped
                return;
            }

            let reqTime = Date.now() - start;

            logger.debug({
                msg: 'Pulled subscription messages',
                source: 'google',
                app: this.app,
                messages: pullRes?.receivedMessages?.length || 0,
                reqTime
            });

            for (let receivedMessage of pullRes?.receivedMessages || []) {
                // Check stopped flag at start of each message for faster shutdown
                if (this.stopped) {
                    logger.info({ msg: 'Stopping message processing due to shutdown', app: this.app });
                    return;
                }

                let processingSuccess = false;
                try {
                    await this.processPulledMessage(
                        receivedMessage?.message?.messageId,
                        Buffer.from(receivedMessage?.message?.data || '', 'base64').toString()
                    );
                    processingSuccess = true;
                } catch (err) {
                    // Processing failed - don't ACK so message will be redelivered
                    logger.error({
                        msg: 'Failed to process subscription message',
                        app: this.app,
                        messageId: receivedMessage?.message?.messageId,
                        err
                    });
                }

                // Only ACK after successful processing
                if (processingSuccess) {
                    try {
                        accessToken = await this.getAccessToken();
                        if (!accessToken) {
                            logger.error({
                                msg: 'Failed to ack subscription message. No access token',
                                app: this.app,
                                messageId: receivedMessage?.message?.messageId
                            });
                        } else {
                            await this.client.request(accessToken, acknowledgeUrl, 'POST', { ackIds: [receivedMessage?.ackId] }, { returnText: true });
                            logger.debug({
                                msg: 'Acked subscription message',
                                app: this.app,
                                messageId: receivedMessage?.message?.messageId
                            });
                        }
                    } catch (err) {
                        // failed to ack
                        logger.error({
                            msg: 'Failed to ack subscription message',
                            app: this.app,
                            messageId: receivedMessage?.message?.messageId,
                            err
                        });
                    }
                }
            }

            await oauth2Apps.setMeta(this.app, { pubSubFlag: null });
        } catch (err) {
            // Transient network errors are expected for long-polling connections
            if (
                [
                    'ENOTFOUND',
                    'EAI_AGAIN',
                    'ETIMEDOUT',
                    'ECONNRESET',
                    'ECONNREFUSED',
                    'UND_ERR_SOCKET',
                    'UND_ERR_CONNECT_TIMEOUT',
                    'UND_ERR_HEADERS_TIMEOUT'
                ].includes(err.code)
            ) {
                logger.warn({ msg: 'Transient error pulling subscription messages', app: this.app, code: err.code });
                return;
            }
            // Detect deleted subscription (expired after 31 days of inactivity) and try to recreate
            if (err.statusCode === 404 || err?.oauthRequest?.response?.error?.code === 404) {
                await this.attemptRecovery('Subscription not found (404)');
                return; // re-enter the pull loop
            }

            logger.error({ msg: 'Failed to pull subscription messages', app: this.app, err });
            throw err;
        }
    }

    async attemptRecovery(reason) {
        let now = Date.now();
        let backoffMs = Math.min(3000 * Math.pow(2, Math.min(this.recoveryAttempts, 20)), 5 * 60 * 1000);
        if (now - this.lastRecoveryAttempt < backoffMs) {
            logger.warn({ msg: 'Skipping subscription recovery (backoff)', app: this.app, reason, recoveryAttempts: this.recoveryAttempts, backoffMs });
            throw new Error(reason);
        }

        this.lastRecoveryAttempt = now;
        this.recoveryAttempts++;

        logger.warn({ msg: 'Attempting subscription recovery', app: this.app, reason, recoveryAttempts: this.recoveryAttempts });

        try {
            await this.getApp(true);
            await oauth2Apps.ensurePubsub(this.appData);
            await this.getClient(true);
            await oauth2Apps.setMeta(this.app, { pubSubFlag: null });
            this.recoveryAttempts = 0;
            logger.info({ msg: 'Successfully recovered Pub/Sub subscription', app: this.app, reason });
        } catch (recoveryErr) {
            logger.error({ msg: 'Failed to recover Pub/Sub subscription', app: this.app, reason, err: recoveryErr });
            throw recoveryErr;
        }
    }

    async getClient(force) {
        if (this.client && !force) {
            return this.client;
        }
        const appData = await this.getApp(force);
        this.client = await oauth2Apps.getClient(appData.id);
        return this.client;
    }

    async getApp(force) {
        if (this.appData && !force) {
            return this.appData;
        }
        this.appData = await oauth2Apps.get(this.app);
        return this.appData;
    }

    async getAccessToken() {
        await this.getClient();
        return await oauth2Apps.getServiceAccessToken(this.appData, this.client);
    }
}

class GooglePubSub {
    constructor(opts) {
        this.opts = opts || {};
        this.call = opts.call;
        this.pubSubInstances = new Map();
    }

    getSubscribersKey() {
        return `${REDIS_PREFIX}oapp:sub`;
    }

    async start() {
        // Backfill apps with baseScopes === 'pubsub' that are missing from the subscribers set
        let apps = await oauth2Apps.backfillPubSubApps();
        for (let app of apps) {
            this.pubSubInstances.set(app, new PubSubInstance(this, { app }));
        }
    }

    async update(app) {
        if (!this.pubSubInstances.has(app)) {
            this.pubSubInstances.set(app, new PubSubInstance(this, { app }));
        }
    }

    async remove(app) {
        if (this.pubSubInstances.has(app)) {
            const instance = this.pubSubInstances.get(app);
            instance.stopped = true; // Stop the loop before removing
            this.pubSubInstances.delete(app);
        }
    }
}

module.exports = { GooglePubSub, PubSubInstance };
