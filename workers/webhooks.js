'use strict';

const fetch = require('node-fetch');
const { redis, notifyQueue } = require('../lib/db');
const settings = require('../lib/settings');
const logger = require('../lib/logger');
const packageData = require('../package.json');

function getAccountKey(account) {
    return `iad:${account}`;
}

notifyQueue.process('*', async job => {
    // validate if we should even process this webhook
    let accountExists = await redis.exists(getAccountKey(job.data.account));
    if (!accountExists) {
        logger.debug({ msg: 'Account is not enabled', action: 'webhook', event: job.name, account: job.data.account });
        return;
    }
    let webhooks = await settings.get('webhooks');
    if (!webhooks) {
        logger.debug({ msg: 'Webhook URL is not set', action: 'webhook', event: job.name, account: job.data.account });
        return;
    }

    logger.trace({ msg: 'Received new notification', webhooks, event: job.name, data: job.data });
    if (!job.data.path) {
        // ignore non-message related events
        return;
    }

    try {
        let res = await fetch(webhooks, {
            method: 'post',
            body: JSON.stringify(job.data),
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': `${packageData.name}/${packageData.version} (+https://imapapi.com)`
            }
        });
        if (!res.ok) {
            throw new Error(`Invalid response: ${res.status} ${res.statusText}`);
        }
    } catch (err) {
        logger.error({ msg: 'Failed posting webhook', webhooks, event: job.name, err });
        throw err;
    }
});
