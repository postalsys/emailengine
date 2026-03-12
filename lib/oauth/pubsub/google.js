'use strict';

const { redis } = require('../../db');
const { REDIS_PREFIX, TRANSIENT_NETWORK_CODES } = require('../../consts');
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
        this._loopTimer = null;
        this._immediateHandle = null;
        this._abortController = null;
        this.recoveryAttempts = 0;
        this.lastRecoveryAttempt = 0;
        // Initialize to true so the first successful pull clears any stale
        // pubSubFlag left in Redis by a previously crashed process
        this._hadPubSubFlag = true;
        this._lastLoopError = null;

        this.checkSchemaVersions()
            .catch(err => {
                logger.error({ msg: 'Failed to process schema versions', err });
            })
            .finally(() => {
                if (!this.stopped) {
                    this.startLoop();
                }
            });
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
                this._lastLoopError = null;
                this._immediateHandle = setImmediate(() => this.startLoop());
            })
            .catch(err => {
                if (this.stopped || err.name === 'AbortError') {
                    return;
                }
                let errKey = [err.message, err.code, err.statusCode].filter(val => val).join('|');
                if (this._lastLoopError !== errKey) {
                    logger.error({ msg: 'Failed to process subscription loop', app: this.app, err });
                    this._lastLoopError = errKey;

                    this._hadPubSubFlag = true;
                    oauth2Apps
                        .setMeta(this.app, {
                            pubSubFlag: {
                                message: `Failed to process subscription loop`,
                                description: [err.message, err.reason, err.code].filter(val => val).join('; ')
                            }
                        })
                        .catch(metaErr => {
                            logger.error({ msg: 'Failed to update pubSubFlag', app: this.app, err: metaErr });
                        });
                }
                this._loopTimer = setTimeout(() => this.startLoop(), err.retryDelay || 3000);
            });
    }

    async checkSchemaVersions() {
        let subscriberApps = await redis.smembers(this.getPubsubAppKey());
        let currentSchemaId = 3;
        for (let subscriberApp of subscriberApps) {
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
        for (let subscriberApp of subscriberApps) {
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

            this._abortController = new AbortController();
            let pullRes = await this.client.request(
                accessToken,
                pullUrl,
                'POST',
                { returnImmediately: false, maxMessages: 100 },
                { signal: this._abortController.signal }
            );
            if (this.stopped) {
                this._abortController = null;
                return;
            }
            this._abortController = null;

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

                let messageId = receivedMessage?.message?.messageId;

                try {
                    await this.processPulledMessage(messageId, Buffer.from(receivedMessage?.message?.data || '', 'base64').toString());
                } catch (err) {
                    // Processing failed - skip ACK so message will be redelivered
                    logger.error({ msg: 'Failed to process subscription message', app: this.app, messageId, err });
                    continue;
                }

                // ACK after successful processing
                try {
                    await this.client.request(accessToken, acknowledgeUrl, 'POST', { ackIds: [receivedMessage?.ackId] }, { returnText: true });
                    logger.debug({ msg: 'Acked subscription message', app: this.app, messageId });
                } catch (err) {
                    logger.error({ msg: 'Failed to ack subscription message', app: this.app, messageId, err });
                }
            }

            if (this._hadPubSubFlag) {
                try {
                    await oauth2Apps.setMeta(this.app, { pubSubFlag: null });
                    this._hadPubSubFlag = false;
                } catch (metaErr) {
                    logger.error({ msg: 'Failed to clear pubSubFlag after successful pull', app: this.app, err: metaErr });
                }
            }
        } catch (err) {
            // Transient network errors are expected for long-polling connections
            if (TRANSIENT_NETWORK_CODES.has(err.code)) {
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
        let backoffMs = this._recoveryBackoffMs();
        if (now - this.lastRecoveryAttempt < backoffMs) {
            let remainingMs = backoffMs - (now - this.lastRecoveryAttempt);
            let err = new Error(reason);
            err.retryDelay = remainingMs;
            throw err;
        }

        this.lastRecoveryAttempt = now;
        this.recoveryAttempts++;

        logger.info({ msg: 'Attempting subscription recovery', app: this.app, reason, recoveryAttempts: this.recoveryAttempts });

        try {
            if (this.stopped) return;
            await this.getApp(true);
            if (this.stopped) return;
            await oauth2Apps.ensurePubsub(this.appData);
            if (this.stopped) return;
            await this.getClient(true);
            if (this.stopped) return;
            await oauth2Apps.setMeta(this.app, { pubSubFlag: null });
            this._hadPubSubFlag = false;
            this.recoveryAttempts = 0;
            logger.info({ msg: 'Successfully recovered Pub/Sub subscription', app: this.app, reason });
        } catch (recoveryErr) {
            let nextBackoffMs = this._recoveryBackoffMs();
            logger.warn({ msg: 'Subscription recovery failed', app: this.app, reason, err: recoveryErr, nextRetryMs: nextBackoffMs });
            recoveryErr.retryDelay = nextBackoffMs;
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

    _recoveryBackoffMs() {
        return Math.min(3000 * Math.pow(2, Math.min(this.recoveryAttempts, 20)), 5 * 60 * 1000);
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
            await this.update(app);
        }
    }

    async update(app) {
        if (this.pubSubInstances.has(app)) {
            this.remove(app);
        }
        this.pubSubInstances.set(app, new PubSubInstance(this, { app }));
    }

    remove(app) {
        if (this.pubSubInstances.has(app)) {
            const instance = this.pubSubInstances.get(app);
            instance.stopped = true;
            clearTimeout(instance._loopTimer);
            clearImmediate(instance._immediateHandle);
            if (instance._abortController) {
                instance._abortController.abort();
            }
            this.pubSubInstances.delete(app);
        }
    }

    stopAll() {
        for (let app of Array.from(this.pubSubInstances.keys())) {
            this.remove(app);
        }
    }
}

module.exports = { GooglePubSub, PubSubInstance };
