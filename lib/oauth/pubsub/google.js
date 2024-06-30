'use strict';

const { redis } = require('../../db');
const { REDIS_PREFIX } = require('../../consts');
const logger = require('../../logger').child({
    component: 'google-subscriber'
});
const { oauth2Apps } = require('../../oauth2-apps');

class PubSubInstance {
    constructor(parent, opts) {
        this.parent = parent;
        this.opts = opts || {};
        this.app = opts.app;

        this.stopped = false;
        this.startLoop();
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
                setTimeout(() => this.startLoop(), 3000);
            });
    }

    async processPulledMessage(messageId, data) {
        logger.info({ msg: 'Processing subscription message', source: 'google', app: this.app, messageId });

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
            let accountId = await redis.hget(`${REDIS_PREFIX}oapp:h:${subscriberApp}`, payload.emailAddress);
            if (accountId) {
                accountIds.add(accountId);
            }
        }

        if (!accountIds.size) {
            logger.info({ msg: 'Failed to match email address with account ID', app: this.app, messageId, emailAddress: payload.emailAddress });
            return;
        }

        try {
            await this.parent.call({ cmd: 'gmailNotify', accounts: Array.from(accountIds), historyId: Number(payload.historyId) || null });
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

        let accessToken = await this.getAccessToken();
        if (!accessToken) {
            logger.error({ msg: 'Failed to retrieve access token', app: this.app });
            throw new Error('Failed to retrieve access token');
        }

        let pullUrl = `https://pubsub.googleapis.com/v1/${this.appData.pubSubSubscription}:pull`;
        let acknowledgeUrl = `https://pubsub.googleapis.com/v1/${this.appData.pubSubSubscription}:acknowledge`;

        try {
            let start = Date.now();

            logger.debug({ msg: 'Pulling subscription messages', source: 'google', app: this.app });
            let pullRes = await this.client.request(accessToken, pullUrl, 'POST', { returnImmediately: false, maxMessages: 100 });
            if (this.stopped) {
                // ignore if stopped
                return;
            }

            logger.debug({
                msg: 'Pulled subscription messages',
                source: 'google',
                app: this.app,
                messages: pullRes?.receivedMessages?.length || 0,
                delay: Date.now() - start
            });

            for (let receivedMessage of pullRes?.receivedMessages || []) {
                try {
                    await this.processPulledMessage(
                        receivedMessage?.message?.messageId,
                        Buffer.from(receivedMessage?.message?.data || '', 'base64url').toString()
                    );
                } finally {
                    // ack the message
                    // might be expired
                    try {
                        accessToken = await this.getAccessToken();
                        if (!accessToken) {
                            logger.error({
                                msg: 'Failed to ack subscription message. No access token',
                                app: this.app,
                                messageId: receivedMessage?.message?.messageId
                            });
                        }

                        await this.client.request(accessToken, acknowledgeUrl, 'POST', { ackIds: [receivedMessage?.ackId] }, { returnText: true });
                        logger.debug({
                            msg: 'Acked subscription message',
                            app: this.app,
                            messageId: receivedMessage?.message?.messageId
                        });
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
        } catch (err) {
            logger.error({ msg: 'Failed to pull subscription messages', app: this.app, err });
            throw err;
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
        let apps = await redis.smembers(this.getSubscribersKey());
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
            this.pubSubInstances.delete(app);
        }
    }
}

module.exports = { GooglePubSub };
