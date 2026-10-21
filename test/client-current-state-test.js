'use strict';

// The connection state the IMAP worker counts every second for /metrics and the dashboard. The
// Gmail API and Graph clients used to read it from Redis, one HGET per account per second, one
// account at a time; it is answered from memory now, so a Redis that is never touched passes.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { BaseClient } = require('../lib/email-client/base-client');
const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');

require('./helpers/redis-teardown')();

const untouchable = new Proxy(
    {},
    {
        get(target, name) {
            throw new Error(`Redis was used: ${String(name)}`);
        }
    }
);

test('currentState() answers from memory on the API clients', async () => {
    for (const Client of [GmailClient, OutlookClient, BaseClient]) {
        const client = Object.assign(Object.create(Client.prototype), { redis: untouchable });
        assert.strictEqual(await client.currentState(), 'disconnected', `${Client.name} without a state`);
        for (const state of ['connecting', 'connected', 'authenticationError', 'connectError', 'disconnected']) {
            client.state = state;
            assert.strictEqual(await client.currentState(), state, `${Client.name} ${state}`);
        }
    }
});
