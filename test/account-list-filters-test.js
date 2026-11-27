'use strict';

// The account listing's filters (several states, a domain, a kind) from the query string to the
// stored records: the shared helpers in lib/account/listing-filters.js, Account#listAccounts()
// against real records, the filter pills of the admin page (lib/ui-routes/list-filters.js and
// account-listing.js), and the query schemas of the admin page and GET /v1/accounts.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');
const { PROVIDER_KINDS, appKindEntries, availableAccountKinds, stateFilterList, normalizeDomainFilter } = require('../lib/account/listing-filters');
const { OAUTH_PROVIDERS } = require('../lib/oauth2-apps');
const { buildFilterBar, listUrl } = require('../lib/ui-routes/list-filters');
const { accountListQuerySchema, accountListView, accountCountLabel } = require('../lib/ui-routes/account-listing');
const { accountListingSchemas } = require('../lib/schemas');
const registerRedisTeardown = require('./helpers/redis-teardown');
const exitWhenStandalone = require('./helpers/exit-standalone');

registerRedisTeardown(redis);
exitWhenStandalone();

const logger = { warn() {}, error() {}, debug() {}, info() {}, trace() {}, child: () => logger };
const call = async message => (message.cmd === 'runIndex' ? 1 : null);
const suffix = crypto.randomBytes(4).toString('hex');

test('listing filter helpers', async t => {
    await t.test('state lists expand "errors" and fold duplicates', () => {
        assert.equal(stateFilterList(undefined), '*');
        assert.equal(stateFilterList([]), '*');
        assert.equal(stateFilterList('*'), '*');
        assert.equal(stateFilterList('connected'), 'connected');
        assert.equal(stateFilterList(['errors', 'connectError', 'paused']), 'authenticationError,connectError,paused');
    });

    await t.test('a domain is compared lowercased, without a pasted "@" or a trailing dot', () => {
        assert.equal(normalizeDomainFilter(' @Acme.COM. '), 'acme.com');
        assert.equal(normalizeDomainFilter(undefined), '');
    });

    await t.test('every OAuth2 provider has a kind', () => {
        // a provider without one would put its accounts in the "oauth2" kind, which no filter selects
        assert.deepEqual(
            Object.keys(OAUTH_PROVIDERS).filter(provider => !PROVIDER_KINDS[provider]),
            []
        );
    });

    await t.test('OAuth2 apps map to the kind of their provider family', () => {
        const apps = [
            { id: 'a1', provider: 'gmailService' },
            { id: 'a2', provider: 'outlook' },
            { id: 'a3', provider: 'somethingNew' }
        ];
        assert.equal(appKindEntries(apps), 'a1=gmail\na2=outlook');
        assert.deepEqual(
            availableAccountKinds(apps).map(entry => entry.value),
            ['imap', 'sending', 'gmail', 'outlook', 'delegated']
        );
        assert.deepEqual(
            availableAccountKinds([]).map(entry => entry.value),
            ['imap', 'sending']
        );
    });
});

test('listAccounts applies the domain and kind filters', async t => {
    const accounts = [];
    t.after(async () => {
        for (const account of accounts) {
            await new Account({ redis, account, secret: await getSecret(), logger, call }).delete().catch(() => false);
        }
    });

    const smtp = { host: 'smtp.example.com', port: 465, secure: true, auth: { user: 'u', pass: 'p' } };
    const seed = async (account, email, data) => {
        accounts.push(account);
        await new Account({ redis, account, secret: await getSecret(), logger, call }).create(Object.assign({ account, name: account, email }, data));
    };
    await seed(`lf-imap-${suffix}`, `a@lf-${suffix}.example`, {
        imap: { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'u', pass: 'p' } },
        smtp
    });
    await seed(`lf-smtp-${suffix}`, `b@eu.lf-${suffix}.example`, { smtp });
    await seed(`lf-other-${suffix}`, `c@lf-${suffix}.example.org`, { smtp });

    const list = async (state, filters) => {
        const listing = await new Account({ redis, secret: await getSecret(), logger, call }).listAccounts(state, '', 0, 50, filters);
        return { state: listing.state, ids: listing.accounts.map(entry => entry.account).sort() };
    };

    assert.deepEqual((await list(false, { domain: `LF-${suffix}.example` })).ids, [`lf-imap-${suffix}`, `lf-smtp-${suffix}`].sort());
    assert.deepEqual((await list(false, { domain: `lf-${suffix}.example`, type: ['sending'] })).ids, [`lf-smtp-${suffix}`]);
    assert.deepEqual((await list(false, { domain: `lf-${suffix}.example`, type: 'imap' })).ids, [`lf-imap-${suffix}`]);
    // the listing reports the state list it applied
    assert.equal((await list(['errors'], { domain: `lf-${suffix}.example` })).state, 'authenticationError,connectError');
});

test('filter bar view model', async t => {
    const filters = [
        {
            name: 'state',
            label: 'Status',
            type: 'multi',
            options: [
                { value: 'connected', label: 'Connected' },
                { value: 'paused', label: 'Paused' },
                { value: 'unset', label: 'Not syncing' }
            ]
        },
        { name: 'domain', label: 'Domain', type: 'text', placeholder: 'example.com' }
    ];

    await t.test('an unfiltered list has idle pills and nothing to clear', () => {
        const bar = buildFilterBar({ path: '/admin/x', current: { state: [] }, keep: ['query'], filters });
        assert.equal(bar.active, false);
        assert.deepEqual(
            bar.pills.map(pill => [pill.name, pill.active]),
            [
                ['state', false],
                ['domain', false]
            ]
        );
        assert.deepEqual(bar.hidden, []);
        assert.equal(bar.clearHref, '/admin/x');
    });

    await t.test('a set pill summarizes its values and drops only itself', () => {
        const current = { state: ['connected', 'paused', 'unset'], domain: 'acme.com', query: 'bob', page: 3 };
        const bar = buildFilterBar({ path: '/admin/x', current, keep: ['query'], filters });
        const [state, domain] = bar.pills;

        assert.equal(state.summary, 'Connected +2');
        assert.equal(domain.summary, 'acme.com');
        assert.equal(state.clearHref, '/admin/x?query=bob&domain=acme.com');
        assert.equal(domain.clearHref, '/admin/x?query=bob&state=connected&state=paused&state=unset');
        // the search stays and the page goes when the filters are cleared
        assert.equal(bar.clearHref, '/admin/x?query=bob');
        assert.deepEqual(bar.hidden, [{ name: 'query', value: 'bob' }]);
        // the topbar search carries the filters, not the search it replaces
        assert.deepEqual(
            bar.searchHidden.map(entry => entry.name),
            ['state', 'state', 'state', 'domain']
        );
    });

    await t.test('a value no longer offered still shows, so it can be cleared', () => {
        const bar = buildFilterBar({ path: '/admin/x', current: { state: ['gone'] }, filters });
        assert.deepEqual(bar.pills[0].options.at(-1), { value: 'gone', label: 'gone', checked: true });
    });

    await t.test('list URLs repeat arrays and leave empty values out', () => {
        assert.equal(listUrl('/p', { a: ['1', '2'], b: '', c: null, d: false, e: 0 }), '/p?a=1&a=2&e=0');
        assert.equal(listUrl('/p', {}), '/p');
    });
});

test('admin accounts list query and view', async t => {
    await t.test('the query takes one or several states, kinds and a domain', () => {
        const { value, error } = accountListQuerySchema.validate({ state: 'errors', type: ['imap', 'gmail'], domain: ' @Acme.com ' });
        assert.equal(error, undefined);
        assert.deepEqual(value.state, ['errors']);
        assert.deepEqual(value.type, ['imap', 'gmail']);
        assert.equal(value.domain, 'acme.com');
        assert.ok(accountListQuerySchema.validate({ type: 'nonsense' }).error);
        assert.ok(accountListQuerySchema.validate({ domain: 'a b' }).error);
    });

    await t.test('page links keep every filter, and the search crumb keeps the filters', () => {
        const current = accountListQuerySchema.validate({ state: ['errors'], domain: 'acme.com', query: 'bob', page: 2 }).value;
        const { filterBar, pageUrl, clearSearchHref } = accountListView(current, [{ id: 'g', provider: 'gmail' }]);
        assert.equal(pageUrl(1), '/admin/accounts?query=bob&state=errors&domain=acme.com');
        assert.equal(pageUrl(3), '/admin/accounts?page=3&query=bob&state=errors&domain=acme.com');
        assert.equal(clearSearchHref, '/admin/accounts?state=errors&domain=acme.com');
        assert.deepEqual(
            filterBar.pills.find(pill => pill.name === 'type').options.map(option => option.value),
            ['imap', 'sending', 'gmail']
        );
    });

    await t.test('the header count names the whole only when narrowed', () => {
        assert.equal(accountCountLabel(40, 40, false), '40');
        assert.equal(accountCountLabel(3, 40, true), '3 of 40');
    });

    await t.test('the API schemas share the domain and kind rules', () => {
        assert.deepEqual(accountListingSchemas.type.validate('delegated').value, ['delegated']);
        assert.ok(accountListingSchemas.type.validate(['imap', 'nope']).error);
        assert.equal(accountListingSchemas.domain.validate('Example.COM.').value, 'example.com');
        assert.equal(accountListingSchemas.domain.validate('@').value, undefined);
    });
});
