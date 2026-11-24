'use strict';

// Unit tests for lib/ui-routes/provider-signin.js: which OAuth2 applications the hosted setup form
// offers when autodiscovery recognizes a Gmail or Microsoft mailbox on the IMAP path.

const test = require('node:test');
const assert = require('node:assert').strict;

const { pickSignInApps } = require('../lib/ui-routes/provider-signin');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const app = (id, extra) => Object.assign({ id, name: `App ${id}`, provider: 'outlook', enabled: true, includeInListing: true, authority: 'common' }, extra);
const ids = list => list.map(entry => entry.id);

test('pickSignInApps', async t => {
    await t.test('offers only interactive applications of the provider', () => {
        const apps = [
            app('outlook'),
            app('gmail', { provider: 'gmail' }),
            app('service', { provider: 'outlookService' }),
            app('pubsub', { provider: 'gmail', baseScopes: 'pubsub' })
        ];

        assert.deepEqual(ids(pickSignInApps(apps, 'outlook', 'user@example.com')), ['outlook']);
        assert.deepEqual(ids(pickSignInApps(apps, 'gmail', 'user@example.com')), ['gmail']);
    });

    await t.test('an organization address is not offered an application limited to personal accounts', () => {
        const apps = [
            app('common'),
            app('organizations', { authority: 'organizations' }),
            app('tenant', { authority: '72f988bf-86f1-41af-91ab-2d7cd011db47' }),
            app('consumers', { authority: 'consumers' })
        ];

        assert.deepEqual(ids(pickSignInApps(apps, 'outlook', 'user@example.com')), ['common', 'organizations', 'tenant']);
    });

    await t.test('a personal address is offered only applications open to personal accounts', () => {
        const apps = [
            app('common'),
            app('organizations', { authority: 'organizations' }),
            app('tenant', { authority: 'contoso.onmicrosoft.com' }),
            app('consumers', { authority: 'consumers' })
        ];

        assert.deepEqual(ids(pickSignInApps(apps, 'outlook', 'user@hotmail.com')), ['common', 'consumers']);
    });

    await t.test('an application without a display title is named only when it has to be told apart', () => {
        const single = pickSignInApps([app('one')], 'outlook', 'user@example.com');
        assert.equal(single[0].displayTitle, null);

        const several = pickSignInApps([app('one'), app('two', { title: 'Work accounts' })], 'outlook', 'user@example.com');
        assert.deepEqual(
            several.map(entry => entry.displayTitle),
            ['App one', 'Work accounts']
        );
    });

    await t.test('nothing to offer for no applications or no provider', () => {
        assert.deepEqual(pickSignInApps([], 'outlook', 'user@example.com'), []);
        assert.deepEqual(pickSignInApps(undefined, 'gmail', 'user@gmail.com'), []);
    });
});
