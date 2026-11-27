'use strict';

// The filter pills of the admin lists besides accounts: the state each list derives for an entry
// (gatewayState, webhookStatus), the listings that filter by it before paging, the OAuth2 apps
// provider filter, the shared listPageView() and the filter definitions in entity-list-filters.js.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { Gateway, gatewayState } = require('../lib/gateway');
const { webhooks, webhookStatus } = require('../lib/webhooks');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { lists } = require('../lib/lists');
const { filterListPage } = require('../lib/tools');
const { listPageView } = require('../lib/ui-routes/list-filters');
const { LIST_FILTER_QUERY, LIST_FILTERS } = require('../lib/ui-routes/entity-list-filters');
const registerRedisTeardown = require('./helpers/redis-teardown');
const exitWhenStandalone = require('./helpers/exit-standalone');

registerRedisTeardown(redis);
exitWhenStandalone();

const suffix = crypto.randomBytes(4).toString('hex');

test('derived list states', async t => {
    await t.test('a gateway is in error after a failed delivery, connected after a good one, unused otherwise', () => {
        assert.equal(gatewayState({ deliveries: 3, lastError: { response: '535' } }), 'error');
        assert.equal(gatewayState({ deliveries: 3 }), 'connected');
        assert.equal(gatewayState({}), 'unused');
    });

    await t.test('a webhook route is disabled, failing or enabled', () => {
        assert.equal(webhookStatus({ enabled: false, webhookErrorFlag: { message: 'x' } }), 'disabled');
        assert.equal(webhookStatus({ enabled: true, webhookErrorFlag: { message: 'x' } }), 'failing');
        assert.equal(webhookStatus({ enabled: true, webhookErrorFlag: null }), 'enabled');
    });

    await t.test('filterListPage applies the extra test before paging', () => {
        const entries = [1, 2, 3, 4, 5, 6].map(n => ({ name: `entry ${n}`, n }));
        const paged = filterListPage(entries, ['name'], 'entry', 1, 2, entry => entry.n % 2 === 0);
        assert.deepEqual(
            paged.entries.map(entry => entry.n),
            [4, 6]
        );
        assert.equal(paged.total, 3);
        assert.equal(paged.pages, 2);
    });
});

test('listings filter by the derived state', async t => {
    const created = { gateways: [], routes: [], apps: [] };
    t.after(async () => {
        for (const gateway of created.gateways) {
            await new Gateway({ redis, gateway }).delete().catch(() => false);
        }
        for (const id of created.routes) {
            await webhooks.del(id).catch(() => false);
        }
        for (const id of created.apps) {
            await oauth2Apps.del(id).catch(() => false);
        }
    });

    await t.test('gateways', async () => {
        const make = async (name, extra) => {
            const gateway = `lpf-${name}-${suffix}`;
            created.gateways.push(gateway);
            await new Gateway({ redis }).create({ gateway, name, host: 'smtp.example.com', port: 587, secure: false });
            if (extra) {
                await redis.hmset(new Gateway({ redis }).getGatewayKey(gateway), extra);
            }
            return gateway;
        };
        const good = await make('good', { deliveries: 5 });
        const bad = await make('bad', { deliveries: 5, lastError: JSON.stringify({ response: '535' }) });
        const idle = await make('idle');

        const list = async state => (await new Gateway({ redis }).listGateways(0, 100, suffix, { state })).gateways.map(entry => entry.gateway).sort();
        assert.deepEqual(await list(['error']), [bad]);
        assert.deepEqual(await list(['connected', 'unused']), [good, idle].sort());
        assert.deepEqual(await list([]), [bad, good, idle].sort());
    });

    await t.test('webhook routes', async () => {
        const make = async (name, enabled, errorFlag) => {
            const { id } = await webhooks.create({ name: `${name} ${suffix}`, enabled, targetUrl: 'https://hooks.example.com/' }, { fn: 'return true;' });
            created.routes.push(id);
            if (errorFlag) {
                await redis.hset(webhooks.getWebhooksContentKey(), `${id}:webhookErrorFlag`, JSON.stringify(errorFlag));
            }
            return id;
        };
        const on = await make('on', true);
        const failing = await make('failing', true, { message: 'Request failed with status code 502' });
        const off = await make('off', false);

        const list = async status => (await webhooks.list(0, 100, suffix, { status })).webhooks.map(entry => entry.id).sort();
        assert.deepEqual(await list(['failing']), [failing]);
        assert.deepEqual(await list(['enabled', 'disabled']), [on, off].sort());
        assert.deepEqual(await list([]), [failing, off, on].sort());
    });

    await t.test('suppression list entries by reason, source and account', async () => {
        const listId = `lpf-${suffix}`;
        const add = (recipient, account, reason, source) => lists.add(listId, recipient, { account, reason, source });
        await add('a@example.com', 'acc-1', 'unsubscribe', 'form');
        await add('b@example.com', 'acc-2', 'unsubscribe', 'api');
        await add('c@example.com', 'acc-1', 'block', 'api');
        t.after(async () => {
            for (const recipient of ['a@example.com', 'b@example.com', 'c@example.com']) {
                await lists.remove(listId, recipient).catch(() => false);
            }
        });

        const list = async opts => {
            const data = await lists.listContent(listId, 0, 20, opts);
            return { total: data.total, recipients: data.addresses.map(entry => entry.recipient), values: data.values };
        };

        assert.deepEqual((await list({ reason: ['unsubscribe'] })).recipients, ['a@example.com', 'b@example.com']);
        assert.deepEqual((await list({ source: ['api'], account: 'acc-1' })).recipients, ['c@example.com']);
        // the values come from the whole list, whatever the filter
        assert.deepEqual((await list({ reason: ['block'], withValues: true })).values, { reason: ['block', 'unsubscribe'], source: ['api', 'form'] });
        // an unfiltered page reads as before, without values
        const plain = await list();
        assert.equal(plain.total, 3);
        assert.equal(plain.values, undefined);
    });

    await t.test('OAuth2 apps by provider', async () => {
        const make = async (provider, extra) => {
            const { id } = await oauth2Apps.create(
                Object.assign(
                    {
                        name: `lpf ${provider} ${suffix}`,
                        provider,
                        enabled: true,
                        clientId: 'id',
                        clientSecret: 'secret',
                        redirectUrl: 'https://example.com/oauth'
                    },
                    extra
                )
            );
            created.apps.push(id);
            return id;
        };
        const gmail = await make('gmail', { baseScopes: 'imap' });
        const mailRu = await make('mailRu');

        const list = async provider => (await oauth2Apps.list(0, 100, { query: suffix, provider })).apps.map(app => app.id);
        assert.deepEqual(await list(['mailRu']), [mailRu]);
        assert.deepEqual(await list(['gmail', 'outlook']), [gmail]);
    });
});

test('listPageView', async t => {
    const filters = [{ name: 'status', label: 'Status', type: 'multi', options: [{ value: 'failing', label: 'Failing' }] }];

    await t.test('page links keep the search, the filters and a non-default page size', () => {
        const view = listPageView({
            path: '/admin/webhooks',
            current: { query: 'crm', status: ['failing'], pageSize: 50, page: 2 },
            filters,
            data: { page: 1, pages: 3 }
        });
        assert.equal(view.prevPage, '/admin/webhooks?pageSize=50&query=crm&status=failing');
        assert.equal(view.nextPage, '/admin/webhooks?page=3&pageSize=50&query=crm&status=failing');
        assert.equal(view.clearSearchHref, '/admin/webhooks?pageSize=50&status=failing');
        assert.equal(view.showPaging, true);
        assert.equal(view.firstPage, false);
        assert.deepEqual(view.searchHidden, [
            { name: 'pageSize', value: 50 },
            { name: 'status', value: 'failing' }
        ]);
    });

    await t.test('the default page size stays out of the links', () => {
        const view = listPageView({ path: '/admin/webhooks', current: { pageSize: 20 }, filters, data: { page: 0, pages: 1 } });
        assert.equal(view.pageUrl(2), '/admin/webhooks?page=2');
        assert.equal(view.showPaging, false);
    });
});

test('entity list filters', async t => {
    await t.test('the account pill names the chosen account and hands the picker its entry', () => {
        const [pill] = LIST_FILTERS.templates({ account: 'acc-1', name: 'Ann', email: 'ann@example.com', state: 'connected' });
        assert.equal(pill.type, 'account');
        assert.equal(pill.summary, 'Ann');
        assert.equal(pill.selected.account, 'acc-1');
        assert.equal(pill.selected.state.name, 'Connected');

        const [unset] = LIST_FILTERS.tokens(null);
        assert.equal(unset.summary, undefined);
        assert.equal(unset.selected, undefined);
    });

    await t.test('the queries take repeated values from the offered set only', () => {
        assert.deepEqual(LIST_FILTER_QUERY.gatewayState.validate('error').value, ['error']);
        assert.ok(LIST_FILTER_QUERY.webhookStatus.validate(['enabled', 'nope']).error);
        assert.deepEqual(LIST_FILTER_QUERY.tokenScope.validate(['*', 'mcp']).value, ['*', 'mcp']);
        assert.equal(LIST_FILTER_QUERY.account.validate('').value, null);
    });
});
