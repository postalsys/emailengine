'use strict';

// Proves that an Outlook (MS Graph) account announces new mail through the periodic recovery pass
// when no change notification ever arrives. The test server's serviceUrl is cleared for the run,
// so the account never even attempts a Graph subscription - a messageNew for it can therefore ONLY
// come from the periodic pass, never from a notification. That is the production case of Graph
// dropping a notification without a `missed` lifecycle event, taken to the extreme. The pass
// interval is shortened for the test run via EENGINE_OUTLOOK_FALLBACK_POLL_INTERVAL (set on the
// live server in test/run-tests.js).

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const testConfig = require('./test-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const webhooksServer = require('./webhooks-server');
const { skipUnlessEnv, ACCESS_TOKEN, waitForCondition, waitForAccountConnected } = require('./helpers');

const server = supertest.agent(`http://127.0.0.1:${config.api.port}`).auth(ACCESS_TOKEN, { type: 'bearer' });

const account = 'outlook-poll-1';

// Comfortably more than two pass intervals (15 s each, the first one jittered) plus Graph delivery
const POLL_TIMEOUT = 120000;

// Talks to a live Microsoft 365 tenant throughout; skipped as a whole without the credentials
const outlookSkip = skipUnlessEnv('OUTLOOK_SERVICE_CLIENT_ID', 'OUTLOOK_SERVICE_CLIENT_SECRET', 'OUTLOOK_SERVICE_TENANT_ID', 'OUTLOOK_SERVICE_ACCOUNT_EMAIL');

test('Outlook periodic recovery announces mail no notification reported', { skip: outlookSkip }, async t => {
    let appId;
    let previousServiceUrl = '';

    t.before(async () => {
        await webhooksServer.init();

        // Without a service URL the client does not try to subscribe at all. With the test
        // server's unreachable one it would, fail, and after the fast retries report connectError,
        // which pauses the periodic pass too
        const stored = await server.get('/v1/settings?serviceUrl=true').expect(200);
        previousServiceUrl = stored.body.serviceUrl || '';
        await server.post('/v1/settings').send({ serviceUrl: '' }).expect(200);
    });

    t.after(async () => {
        // Leave the shared live server as it was for the other test files
        await server.delete(`/v1/account/${account}`).catch(() => {});
        if (appId) {
            await server.delete(`/v1/oauth2/${appId}`).catch(() => {});
        }
        await server
            .post('/v1/settings')
            .send({ serviceUrl: previousServiceUrl })
            .catch(() => {});
        await webhooksServer.quit();
    });

    await t.test('create the Outlook Service OAuth2 app and register the account', { timeout: 30000 }, async () => {
        const app = await server
            .post('/v1/oauth2')
            .send({
                name: 'Outlook Service Poll Test App',
                provider: 'outlookService',
                baseScopes: 'api',
                clientId: process.env.OUTLOOK_SERVICE_CLIENT_ID,
                clientSecret: process.env.OUTLOOK_SERVICE_CLIENT_SECRET,
                authority: process.env.OUTLOOK_SERVICE_TENANT_ID
            })
            .expect(200);
        appId = app.body.id;
        assert.ok(appId);

        await server
            .post('/v1/account')
            .send({
                account,
                name: 'Outlook Poll Test',
                email: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL,
                oauth2: {
                    provider: appId,
                    auth: { user: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL }
                }
            })
            .expect(200);
    });

    await t.test('wait until the account connects, with no subscription', { timeout: testConfig.OUTLOOK_TIMEOUT }, async () => {
        await waitForAccountConnected(server, account, testConfig.OUTLOOK_TIMEOUT);
    });

    const subject = `Outlook poll test ${Date.now()}`;
    const inboxAnnouncements = () =>
        (webhooksServer.webhooks.get(account) || []).filter(
            wh => wh.event === 'messageNew' && wh.data?.subject === subject && wh.data?.messageSpecialUse === '\\Inbox'
        );

    await t.test('a message sent to the account is announced by the periodic pass', { timeout: POLL_TIMEOUT + 60000 }, async () => {
        await server
            .post(`/v1/account/${account}/submit`)
            .send({
                to: [{ name: 'Outlook Poll Test', address: process.env.OUTLOOK_SERVICE_ACCOUNT_EMAIL }],
                subject,
                text: 'Announced without a change notification'
            })
            .expect(200);

        await waitForCondition(async () => inboxAnnouncements().length > 0, {
            interval: 2000,
            timeout: POLL_TIMEOUT,
            message: 'no messageNew from the periodic pass'
        });
    });

    await t.test('later passes do not announce it again', { timeout: 60000 }, async () => {
        // two more pass intervals
        await new Promise(resolve => setTimeout(resolve, 35000));
        assert.equal(inboxAnnouncements().length, 1);
    });

    await t.test('Run sync accepts a start within 30 days and refuses an older one', { timeout: 30000 }, async () => {
        const manualPasses = async () => {
            const res = await server.get('/metrics').expect(200);
            const line = res.text.split('\n').find(entry => entry.startsWith('outlook_missed_recovery{') && entry.includes('reason="manual"'));
            return line ? Number(line.split(' ').pop()) : 0;
        };
        const before = await manualPasses();

        const recent = await server
            .put(`/v1/account/${account}/sync`)
            .send({ sync: true, since: new Date(Date.now() - 60 * 60 * 1000).toISOString() })
            .expect(200);
        assert.equal(recent.body.sync, true);

        // the pass runs in the account's worker, after the request has been answered
        await waitForCondition(async () => (await manualPasses()) > before, { timeout: 20000, message: 'the manual pass did not run' });

        await server
            .put(`/v1/account/${account}/sync`)
            .send({ sync: true, since: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString() })
            .expect(400);

        await server
            .put(`/v1/account/${account}/sync`)
            .send({ sync: true, since: new Date(Date.now() + 60 * 60 * 1000).toISOString() })
            .expect(400);
    });
});
