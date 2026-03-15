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
        // Initialize to true so the first successful pull clears any stale
        // pubSubFlag left in Redis by a previously crashed process
        this._hadPubSubFlag = true;
        // Track whether we have already reported an error this session
        // (separate from _hadPubSubFlag which tracks stale flag clearing)
        this._pubSubFlagSetThisSession = false;
        this._lastLoopError = null;
        this._consecutiveErrors = 0;
        this._recoveryAttempts = 0;

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
            .then(messageCount => {
                if (this.stopped) {
                    return;
                }
                this._lastLoopError = null;
                this._consecutiveErrors = 0;
                this._recoveryAttempts = 0;
                if (messageCount > 0) {
                    this._immediateHandle = setImmediate(() => this.startLoop());
                } else {
                    // Add a small delay when no messages were received to prevent
                    // tight loops if Google returns empty responses immediately
                    this._loopTimer = setTimeout(() => this.startLoop(), 1000);
                }
            })
            .catch(err => {
                if (this.stopped || err.name === 'AbortError') {
                    return;
                }
                let errKey = [err.message, err.code, err.statusCode].filter(val => val).join('|');
                if (this._lastLoopError !== errKey) {
                    logger.error({ msg: 'Failed to process subscription loop', app: this.app, err });
                    this._lastLoopError = errKey;

                    this._setPubSubFlag({
                        message: 'Failed to process subscription loop',
                        description: [err.message, err.reason, err.code].filter(val => val).join('; ')
                    }).catch(() => {});
                }
                this._consecutiveErrors++;
                let retryDelay = err.retryDelay || this._backoffMs(this._consecutiveErrors);
                this._loopTimer = setTimeout(() => this.startLoop(), retryDelay);
            });
    }

    async checkSchemaVersions() {
        let subscriberApps = await redis.smembers(this.getPubsubAppKey());
        let currentSchemaId = 3;
        for (let subscriberApp of subscriberApps) {
            if (this.stopped) return;
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
        logger.debug({ msg: 'Processing subscription message', source: 'google', app: this.app, messageId, data });

        let payload;
        try {
            payload = JSON.parse(data);
        } catch (err) {
            logger.error({ msg: 'Failed to process subscription message', source: 'google', app: this.app, messageId, data, err });
            return;
        }

        if (!payload?.emailAddress || !payload?.historyId) {
            logger.warn({
                msg: 'Ignoring Pub/Sub message with missing required fields',
                source: 'google',
                app: this.app,
                messageId,
                hasPayload: !!payload,
                hasEmailAddress: !!payload?.emailAddress,
                hasHistoryId: !!payload?.historyId
            });
            return;
        }

        let subscriberApps = await redis.smembers(this.getPubsubAppKey());
        let accountIds = new Set();
        for (let subscriberApp of subscriberApps) {
            let accountId = await redis.hget(`${REDIS_PREFIX}oapp:h:${subscriberApp}`, payload.emailAddress.toLowerCase());
            if (accountId) {
                accountIds.add(accountId);
            }
        }

        if (!accountIds.size) {
            logger.info({ msg: 'Failed to match email address with account ID', app: this.app, subscriberApps, messageId, emailAddress: payload.emailAddress });
            return;
        }

        await this.parent.call({ cmd: 'externalNotify', accounts: [...accountIds], historyId: Number(payload.historyId) || null });
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
            let pullStartTime = Date.now();

            this._abortController = new AbortController();
            let pullTimeoutId = setTimeout(() => this._abortController.abort(), 5 * 60 * 1000);
            let pullRes;
            try {
                pullRes = await this.client.request(
                    accessToken,
                    pullUrl,
                    'POST',
                    { returnImmediately: false, maxMessages: 100 },
                    { signal: this._abortController.signal }
                );
            } finally {
                clearTimeout(pullTimeoutId);
                this._abortController = null;
            }
            if (this.stopped) {
                return;
            }

            let reqTime = Date.now() - pullStartTime;

            logger.debug({
                msg: 'Pulled subscription messages',
                source: 'google',
                app: this.app,
                messages: pullRes?.receivedMessages?.length || 0,
                reqTime
            });

            // Collect ackIds for batch acknowledgement
            let ackIds = [];

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

                if (receivedMessage?.ackId) {
                    ackIds.push(receivedMessage.ackId);
                }
            }

            // Batch ACK all successfully processed messages
            if (ackIds.length > 0) {
                // Refresh access token if the pull took a long time (token may be near expiration)
                let elapsed = Date.now() - pullStartTime;
                if (elapsed > 4 * 60 * 1000) {
                    try {
                        accessToken = await this.getAccessToken();
                    } catch (err) {
                        logger.warn({ msg: 'Failed to refresh access token before ACK, using original', app: this.app, err });
                    }
                }

                try {
                    await this.client.request(accessToken, acknowledgeUrl, 'POST', { ackIds }, { returnText: true });
                    logger.debug({ msg: 'Batch acked subscription messages', app: this.app, count: ackIds.length });
                } catch (err) {
                    logger.warn({ msg: 'Batch ACK failed, retrying once', app: this.app, count: ackIds.length, err });
                    try {
                        await new Promise(resolve => setTimeout(resolve, 1000));
                        await this.client.request(accessToken, acknowledgeUrl, 'POST', { ackIds }, { returnText: true });
                        logger.info({ msg: 'Batch ACK retry succeeded', app: this.app, count: ackIds.length });
                    } catch (retryErr) {
                        logger.error({ msg: 'Batch ACK retry also failed, messages will be redelivered', app: this.app, count: ackIds.length, err: retryErr });
                    }
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

            return ackIds.length;
        } catch (err) {
            // Manual timeout abort or shutdown - not an error, just restart the loop
            if (err.name === 'AbortError') {
                throw err;
            }
            // Transient network errors are expected for long-polling connections
            if (TRANSIENT_NETWORK_CODES.has(err.code)) {
                logger.warn({ msg: 'Transient error pulling subscription messages', app: this.app, code: err.code });
                err.retryDelay = 5000;
                throw err;
            }
            // Rate limited by Google API - respect Retry-After header
            if (err.statusCode === 429) {
                let retryDelay = (err.retryAfter ? err.retryAfter * 1000 : null) || 30000;
                logger.warn({ msg: 'Rate limited by Google Pub/Sub API', app: this.app, retryAfterSec: err.retryAfter });
                err.retryDelay = retryDelay;
                throw err;
            }
            // Detect deleted subscription (expired after 31 days of inactivity) and try to recreate
            if (err.statusCode === 404 || err?.oauthRequest?.response?.error?.code === 404) {
                await this.attemptRecovery('Subscription not found (404)');
                return; // re-enter the pull loop
            }

            // Authentication or authorization failure -- set operator-visible flag and let startLoop retry with backoff.
            // 401: token refresh happens automatically via getServiceAccessToken() on next run().
            // 403: permanent until operator fixes IAM permissions; retrying ensurePubsub wastes API calls.
            if (err.statusCode === 401 || err.statusCode === 403) {
                logger.error({
                    msg: 'Authentication/authorization error pulling subscription messages',
                    app: this.app,
                    statusCode: err.statusCode,
                    err
                });
                if (!this._pubSubFlagSetThisSession) {
                    await this._setPubSubFlag({
                        message:
                            err.statusCode === 401
                                ? 'Service account access token expired or revoked'
                                : 'Insufficient permissions to pull from the subscription',
                        description: [err.message, err.reason, err.code].filter(val => val).join('; ')
                    });
                }
                throw err;
            }

            logger.error({ msg: 'Failed to pull subscription messages', app: this.app, err });
            throw err;
        }
    }

    async attemptRecovery(reason) {
        this._recoveryAttempts++;
        if (this._recoveryAttempts > 5) {
            throw new Error(`Recovery attempted ${this._recoveryAttempts} times without a successful pull; backing off`);
        }

        logger.info({ msg: 'Attempting subscription recovery', app: this.app, reason, attempt: this._recoveryAttempts });

        try {
            if (this.stopped) return;
            await this.getApp(true);
            if (this.stopped) return;
            await oauth2Apps.ensurePubsub(this.appData);
            if (this.stopped) return;

            // Verify recovery actually created a subscription
            await this.getApp(true);
            if (!this.appData.pubSubSubscription) {
                throw new Error('Pub/Sub setup completed but subscription is still missing');
            }

            if (this.stopped) return;
            await this.getClient(true);
            if (this.stopped) return;
            await oauth2Apps.setMeta(this.app, { pubSubFlag: null });
            this._hadPubSubFlag = false;
            this._pubSubFlagSetThisSession = false;
            logger.info({ msg: 'Successfully recovered Pub/Sub subscription', app: this.app, reason });
        } catch (recoveryErr) {
            logger.warn({ msg: 'Subscription recovery failed', app: this.app, reason, err: recoveryErr });
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
        let result = await oauth2Apps.get(this.app);
        if (!result) {
            logger.info({ msg: 'App data not found in getApp, removing subscription instance', app: this.app });
            this.stopped = true;
            this.parent.remove(this.app);
            throw new Error('App no longer exists');
        }
        this.appData = result;
        return this.appData;
    }

    async getAccessToken() {
        await this.getClient();
        return await oauth2Apps.getServiceAccessToken(this.appData, this.client);
    }

    _setPubSubFlag(flag) {
        this._hadPubSubFlag = true;
        this._pubSubFlagSetThisSession = true;
        return oauth2Apps.setMeta(this.app, { pubSubFlag: flag }).catch(metaErr => {
            logger.error({ msg: 'Failed to update pubSubFlag', app: this.app, err: metaErr });
        });
    }

    _backoffMs(attempts) {
        let base = Math.min(3000 * Math.pow(2, Math.min(attempts, 20)), 5 * 60 * 1000);
        return Math.floor(base * (0.5 + Math.random() * 0.5));
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
        for (let app of [...this.pubSubInstances.keys()]) {
            this.remove(app);
        }
    }
}

module.exports = { GooglePubSub, PubSubInstance };
