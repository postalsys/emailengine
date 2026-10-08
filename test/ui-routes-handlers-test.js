'use strict';

// Admin UI route handlers from lib/ui-routes/, driven directly with a fake request and toolkit:
// the error paths of the webhook, template, OAuth2 app and account forms, the listings, the
// hosted-form success redirect, the unsubscribe form and the export download. Storage is stubbed
// on the shared module objects the handlers call through; what is left touches Redis db 13 only
// through keys unique to this run.

process.env.EENGINE_SECRET = process.env.EENGINE_SECRET || 'ui-routes-handlers-test-secret';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const pathlib = require('node:path');
const { finished } = require('node:stream/promises');

const tools = require('../lib/tools');
const { Account } = require('../lib/account');
const { Export } = require('../lib/export');
const { webhooks } = require('../lib/webhooks');
const { templates } = require('../lib/templates');
const { lists } = require('../lib/lists');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { gt } = require('../lib/translations');
const getSecret = require('../lib/get-secret');
const { redis } = require('../lib/db');
const { REDIS_PREFIX, NONCE_BYTES } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

const RUN = crypto.randomBytes(6).toString('hex');
const SECRET = 'ui-routes-handlers-test-service-secret';

registerRedisTeardown(redis, async () => {
    let cursor = '0';
    do {
        let [next, keys] = await redis.scan(cursor, 'MATCH', `${REDIS_PREFIX}*${RUN}*`, 'COUNT', 1000);
        cursor = next;
        if (keys.length) {
            await redis.del(...keys);
        }
    } while (cursor !== '0');
});

const logger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

// Registers one lib/ui-routes module on a recording server and returns a route finder
function capture(modulePath, call = async () => ({})) {
    const routes = [];
    const server = new Proxy(
        { route: cfg => routes.push(...[].concat(cfg)), auth: { settings: { default: 'session' }, default() {} } },
        { get: (target, prop) => (prop in target ? target[prop] : () => {}) }
    );
    require(modulePath)({ server, call });
    return (method, path) => {
        const found = routes.find(cfg => cfg.path === path && [].concat(cfg.method).includes(method));
        assert.ok(found, `${method} ${path} is registered`);
        return found;
    };
}

function makeToolkit() {
    const answers = { views: [], redirects: [] };
    const takeover = function () {
        this.tookOver = true;
        return this;
    };
    return {
        answers,
        view(template, context, options) {
            const res = { template, context, options, takeover };
            answers.views.push(res);
            return res;
        },
        redirect(url) {
            const res = { redirect: url, takeover };
            answers.redirects.push(url);
            return res;
        },
        response(source) {
            const res = { source, headers: {} };
            res.type = () => res;
            res.header = (key, value) => {
                res.headers[key] = value;
                return res;
            };
            return res;
        }
    };
}

function makeRequest({ payload, query, params } = {}) {
    const flashes = [];
    return {
        flashes,
        payload,
        query: query || {},
        params: params || {},
        headers: { 'user-agent': 'test-agent' },
        info: { remoteAddress: '10.0.0.1' },
        logger,
        app: { gt, ip: '198.51.100.23' },
        auth: { isAuthenticated: true, credentials: { user: 'admin' }, artifacts: {} },
        async flash(message) {
            flashes.push(message);
        }
    };
}

// Replaces methods on shared module objects for one test, restoring them afterwards
function stub(t, target, methods) {
    const original = {};
    for (const [name, fn] of Object.entries(methods)) {
        original[name] = target[name];
        target[name] = fn;
    }
    t.after(() => Object.assign(target, original));
}

test('accounts listing', async t => {
    const route = capture('../lib/ui-routes/account-routes', async ({ cmd }) => (cmd === 'runIndex' ? 1 : {}));

    await t.test('a row whose account fails to load keeps its id, name and address', async t => {
        stub(t, Account.prototype, {
            async listAccounts() {
                return { total: 1, page: 0, pages: 1, accounts: [{ account: 'broken-1', name: 'Broken', email: 'broken@example.com', state: 'connected' }] };
            },
            async loadAccountData() {
                throw new Error('Delegated account loop');
            }
        });

        const h = makeToolkit();
        await route('GET', '/admin/accounts').handler(makeRequest({ query: { page: 1, pageSize: 20 } }), h);

        const row = h.answers.views[0].context.accounts[0];
        assert.equal(row.account, 'broken-1');
        assert.equal(row.name, 'Broken');
        assert.equal(row.email, 'broken@example.com');
        assert.equal(row.delegationError, 'Delegated account loop');
    });

    await t.test('a long listing renders a window of page links, not one per page', async t => {
        stub(t, Account.prototype, {
            async listAccounts() {
                return { total: 100000, page: 2499, pages: 5000, accounts: [] };
            }
        });

        const h = makeToolkit();
        await route('GET', '/admin/accounts').handler(makeRequest({ query: { page: 2500, pageSize: 20 } }), h);

        const links = h.answers.views[0].context.pageLinks;
        assert.ok(links.length <= 9, `saw ${links.length} entries`);
        assert.deepEqual(
            links.map(link => (link.gap ? '...' : link.title)),
            [1, '...', 2498, 2499, 2500, 2501, 2502, '...', 5000]
        );
        assert.equal(links.find(link => link.active).title, 2500);
    });
});

test('hosted form success page', async t => {
    const route = capture('../lib/ui-routes/account-routes');
    stub(t, tools, { getServiceSecret: async () => SECRET });

    await t.test('without a redirect URL it points at the account page with the id encoded', async t => {
        stub(t, Account.prototype, {
            async create() {
                return { account: 'o"brien#/x', state: 'new' };
            }
        });

        const n = crypto.randomBytes(NONCE_BYTES).toString('base64url') + RUN;
        const { data, signature } = tools.getSignedFormDataSync(SECRET, { n, t: Date.now() }, true);

        const h = makeToolkit();
        await route('POST', '/accounts/new/imap/server').handler(
            makeRequest({
                payload: {
                    data,
                    sig: signature,
                    email: 'user@example.com',
                    imap_host: 'imap.example.com',
                    imap_port: 993,
                    smtp_host: 'smtp.example.com',
                    smtp_port: 465
                }
            }),
            h
        );

        assert.equal(h.answers.views[0].template, 'redirect');
        assert.equal(h.answers.views[0].context.httpRedirectUrl, '/admin/accounts/o%22brien%23%2Fx');
    });
});

test('webhook route forms', async t => {
    const route = capture('../lib/ui-routes/admin-entities-routes');

    await t.test('malformed filter JSON re-renders the new form with the field error', async t => {
        let created = false;
        stub(t, webhooks, {
            async create() {
                created = true;
            }
        });

        const h = makeToolkit();
        const request = makeRequest({ payload: { name: 'Route', contentFnJson: '{not json', contentMapJson: '', customHeaders: '' } });
        await route('POST', '/admin/webhooks/new').handler(request, h);

        assert.equal(created, false);
        assert.equal(h.answers.views[0].template, 'webhooks/new');
        assert.deepEqual(h.answers.views[0].context.errors, { contentFnJson: 'Invalid JSON' });
    });

    await t.test('malformed map JSON re-renders the edit form with the field error', async t => {
        stub(t, webhooks, {
            async update() {
                throw new Error('not reached');
            },
            async get(id) {
                return { id, name: 'Route' };
            }
        });

        const h = makeToolkit();
        const request = makeRequest({ payload: { webhook: 'w1', name: 'Route', contentFnJson: '', contentMapJson: '"x', customHeaders: '' } });
        await route('POST', '/admin/webhooks/edit').handler(request, h);

        assert.equal(h.answers.views[0].template, 'webhooks/edit');
        assert.deepEqual(h.answers.views[0].context.errors, { contentMapJson: 'Invalid JSON' });
    });

    await t.test('a form posted without the headers field validates to an empty header list', () => {
        for (const path of ['/admin/webhooks/new', '/admin/webhooks/edit']) {
            const schema = route('POST', path).options.validate.payload;
            const { value, error } = schema.validate({ webhook: 'w1', name: 'Route' }, { stripUnknown: true });
            assert.equal(error, undefined);
            assert.equal(value.customHeaders, '', path);
        }
    });
});

test('template forms', async t => {
    const route = capture('../lib/ui-routes/admin-entities-routes');

    await t.test('creating a template for an unknown account is refused before it is stored', async t => {
        let created = false;
        stub(t, templates, {
            async create() {
                created = true;
                return { id: 'x' };
            }
        });

        const h = makeToolkit();
        const request = makeRequest({ payload: { account: `missing-${RUN}`, name: 'T', format: 'html', subject: 's', contentHtml: '<p>x</p>' } });
        await route('POST', '/admin/templates/new').handler(request, h);

        assert.equal(created, false);
        assert.deepEqual(h.answers.redirects, ['/admin/templates']);
        assert.match(request.flashes[0].message, /No account found/);
    });

    await t.test('a template whose account is gone still opens', async t => {
        stub(t, templates, {
            async get(id) {
                return { id, account: `gone-${RUN}`, name: 'T', format: 'html', content: { subject: 's' } };
            }
        });

        for (const path of ['/admin/templates/template/{template}', '/admin/templates/template/{template}/edit']) {
            const h = makeToolkit();
            await route('GET', path).handler(makeRequest({ params: { template: 'tpl1' } }), h);
            assert.equal(h.answers.views.length, 1, path);
            assert.equal(h.answers.views[0].context.account, undefined, path);
            assert.equal(h.answers.views[0].context.accountTemplatesLink, '/admin/templates', path);
        }
    });
});

test('worker account page', async t => {
    const threads = [{ threadId: 3, type: 'imap', description: 'IMAP worker', accounts: 2 }];
    const route = capture('../lib/ui-routes/internals-routes', async ({ cmd }) => {
        switch (cmd) {
            case 'threads':
                return threads;
            case 'worker-accounts':
                return { accounts: ['present-1', 'deleted-1'], total: 2, page: 1, pages: 1 };
            case 'runIndex':
                return 1;
        }
        return {};
    });

    await t.test('an assigned account that no longer exists gets a placeholder row', async t => {
        stub(t, Account.prototype, {
            async loadAccountData() {
                if (this.account === 'deleted-1') {
                    const err = new Error('Account record was not found for requested ID');
                    err.output = { statusCode: 404 };
                    throw err;
                }
                return { account: this.account, name: 'Present', email: 'p@example.com', state: 'connected' };
            }
        });

        const h = makeToolkit();
        await route('GET', '/admin/internals/thread/{threadId}').handler(makeRequest({ params: { threadId: 3 }, query: { page: 1, pageSize: 20 } }), h);

        const rows = h.answers.views[0].context.accounts;
        assert.deepEqual(
            rows.map(row => row.account),
            ['present-1', 'deleted-1']
        );
        assert.equal(rows[1].stateLabel.name, 'Unknown');
    });
});

// All five special-use folder overrides have to survive the edit form. Only sentMailPath was in the
// loop that copies the submitted values onto the account, so the other four were settable over
// PUT /v1/account/{account} alone - and a form that offered them while the loop ignored four would
// have been worse than not offering them at all.
//
// Every payload here goes through the route's OWN joi schema first, as hapi does. That is not a detail:
// the first version of these fields carried `.default(null)`, so joi inserted a null for every input
// the browser had not sent, and a save made from a page that does not show them - the IMAP section is
// hidden for an account whose IMAP the operator switched off - wiped all five. A test that handed the
// handler a raw payload could not see it.
test('account edit form stores every special-use folder override', async t => {
    const account = `edit-paths-${RUN}`;
    const route = capture('../lib/ui-routes/account-routes', async ({ cmd }) => (cmd === 'runIndex' ? 1 : {}));
    const editRoute = route('POST', '/admin/accounts/{account}/edit');

    // What hapi hands the handler after validation
    const validated = payload => {
        const { value, error } = editRoute.options.validate.payload.validate(payload, editRoute.options.validate.options);
        assert.ifError(error);
        return value;
    };

    // The same field-encryption secret the handler resolves through getSecret(), or the stored
    // password it reads back cannot be decrypted and every load logs a failure
    const accountObject = new Account({ redis, account, secret: await getSecret(), call: async ({ cmd }) => (cmd === 'runIndex' ? 1 : {}), logger });
    await accountObject.create({
        account,
        name: 'Folders',
        email: 'folders@example.com',
        imap: { host: 'imap.example.com', port: 993, secure: true, auth: { user: 'u', pass: 'p' } },
        smtp: { host: 'smtp.example.com', port: 465, secure: true, auth: { user: 'u', pass: 'p' } }
    });
    t.after(() => accountObject.delete().catch(() => false));

    const submitted = {
        sentMailPath: 'Sent Items',
        draftsMailPath: 'Drafts/Mine',
        junkMailPath: 'Spam',
        trashMailPath: 'Deleted Items',
        archiveMailPath: 'Archive/2026'
    };

    // What the browser posts for an account whose IMAP section is shown
    const formFields = {
        name: 'Folders',
        email: 'folders@example.com',
        customHeaders: '',
        imap: 'on',
        imap_auth_user: 'u',
        imap_host: 'imap.example.com',
        imap_port: 993,
        imap_secure: 'on',
        imap_disabled: ''
    };

    const save = async payload => {
        const h = makeToolkit();
        await editRoute.handler(makeRequest({ params: { account }, payload: validated(payload) }), h);
        return h;
    };

    const h = await save(Object.assign({}, formFields, Object.fromEntries(Object.entries(submitted).map(([key, value]) => [`imap_${key}`, value]))));
    assert.deepEqual(h.answers.redirects, [`/admin/accounts/${account}`], 'the save redirects to the account page');

    const stored = await accountObject.loadAccountData();
    for (const [key, value] of Object.entries(submitted)) {
        assert.equal(stored.imap[key], value, `imap.${key} was not stored`);
    }

    // An emptied input unsets the override, which is the only way to remove one from the form
    await save(
        Object.assign({}, formFields, Object.fromEntries(Object.keys(submitted).map(key => [`imap_${key}`, key === 'junkMailPath' ? '' : submitted[key]])))
    );

    const cleared = await accountObject.loadAccountData();
    assert.ok(!cleared.imap.junkMailPath, 'an emptied override is unset');
    assert.equal(cleared.imap.sentMailPath, submitted.sentMailPath, 'the others are untouched');

    // A save from a page that never showed the inputs leaves every override alone. This is the case
    // `.default(null)` broke: joi filled in five nulls and an unrelated save wiped the lot.
    await save(Object.assign({}, formFields, { name: 'Renamed', imap_disabled: 'on' }));

    const afterUnrelatedSave = await accountObject.loadAccountData();
    for (const [key, value] of Object.entries(submitted)) {
        if (key === 'junkMailPath') {
            continue;
        }
        assert.equal(afterUnrelatedSave.imap[key], value, `imap.${key} was wiped by a save that never showed it`);
    }
    assert.equal(afterUnrelatedSave.name, 'Renamed', 'the save itself went through');
});

test('unsubscribe form', async t => {
    const route = capture('../lib/ui-routes/unsubscribe-routes');
    stub(t, tools, { getServiceSecret: async () => SECRET });

    await t.test('records the client address, not the proxy in front of it', async t => {
        const added = [];
        stub(t, lists, {
            async add(listId, recipient, meta) {
                added.push(meta);
                return false;
            }
        });
        stub(t, Account.prototype, {
            async loadAccountData() {
                return { account: this.account };
            }
        });

        const { data, signature } = tools.getSignedFormDataSync(SECRET, { act: 'unsub', acc: 'acc-1', list: 'news', rcpt: 'r@example.com' }, true);
        const h = makeToolkit();
        await route('POST', '/unsubscribe/address').handler(makeRequest({ payload: { data, sig: signature, action: 'unsubscribe' } }), h);

        assert.equal(added.length, 1);
        assert.equal(added[0].remoteAddress, '198.51.100.23');
    });
});

test('OAuth2 app forms', async t => {
    const route = capture('../lib/ui-routes/oauth-config-routes');
    stub(t, oauth2Apps, {
        async list() {
            return { apps: [] };
        }
    });

    const payload = () => ({
        provider: 'gmailService',
        name: 'Service app',
        authMethod: 'externalAccount',
        externalAccount: '{"type":"external_account","credential_source":{"url":"http://metadata"}}',
        serviceKey: '-----BEGIN PRIVATE KEY-----',
        clientSecret: 'secret',
        extraScopes: '',
        skipScopes: ''
    });

    await t.test('a failed create does not echo the submitted credentials', async t => {
        stub(t, oauth2Apps, {
            async create() {
                throw new Error('Storage failure');
            }
        });

        const h = makeToolkit();
        await route('POST', '/admin/config/oauth/new').handler(makeRequest({ payload: payload() }), h);

        const context = h.answers.views[0].context;
        assert.equal(context.values.externalAccount, '');
        assert.equal(context.values.serviceKey, '');
        assert.equal(context.values.clientSecret, '');
        assert.equal(context.values.name, 'Service app');
        assert.equal(context.actionCreate, true);
    });

    // The Gmail API forms link here to register a Pub/Sub app, and the link has to land on that mode
    await t.test('the new app form preselects the Pub/Sub base scope for a service account only', async () => {
        const newRoute = route('GET', '/admin/config/oauth/new');
        const query = q => newRoute.options.validate.query.validate(q, newRoute.options.validate.options);

        const pubsub = query({ provider: 'gmailService', baseScopes: 'pubsub' });
        assert.ifError(pubsub.error);
        let h = makeToolkit();
        await newRoute.handler(makeRequest({ query: pubsub.value }), h);
        assert.equal(h.answers.views[0].context.baseScopesPubsub, true);
        assert.equal(h.answers.views[0].context.baseScopesImap, false);

        // an interactive Gmail app has no Pub/Sub mode, so the hint is ignored there
        h = makeToolkit();
        await newRoute.handler(makeRequest({ query: query({ provider: 'gmail', baseScopes: 'pubsub' }).value }), h);
        assert.equal(h.answers.views[0].context.baseScopesPubsub, false);
        assert.equal(h.answers.views[0].context.baseScopesImap, true);

        assert.ok(query({ provider: 'gmailService', baseScopes: 'imap' }).error, 'only the Pub/Sub preselect is accepted');
    });

    // The detection itself is covered in test/oauth-gmail-api-mode-test.js against the pure
    // isSendOnlyGmailApp(); what this asserts is that the page actually carries the answer
    await t.test('the app page reports a send-only service account', async t => {
        stub(t, oauth2Apps, {
            async get(id) {
                // What the form's send-only preset stores: the send scope, and a skipScopes entry that
                // takes the api-mode default (gmail.modify) back out of the requested list
                return { id, provider: 'gmailService', baseScopes: 'api', extraScopes: ['gmail.send'], skipScopes: ['gmail.modify'], name: 'App' };
            },
            async listAccounts() {
                return { accounts: [], total: 0, pages: 0, page: 0 };
            }
        });

        const h = makeToolkit();
        await route('GET', '/admin/config/oauth/app/{app}').handler(makeRequest({ params: { app: 'app-1' }, query: {} }), h);

        assert.equal(h.answers.views[0].context.isSendOnlyGmail, true);
    });

    await t.test('the edit form keeps the authentication method locked on a validation error', async t => {
        stub(t, oauth2Apps, {
            async get(id) {
                return { id, provider: 'gmailService', authMethod: 'serviceKey', serviceKey: 'stored' };
            }
        });

        const h = makeToolkit();
        const request = makeRequest({ payload: Object.assign(payload(), { app: 'app-1' }) });
        const res = await route('POST', '/admin/config/oauth/edit').options.validate.failAction(request, h, { details: [{ path: 'name', message: 'bad' }] });

        assert.equal(res.tookOver, true);
        const context = h.answers.views[0].context;
        assert.equal(context.authMethodLocked, true);
        assert.equal(context.authMethodIsServiceKey, true, 'the stored method, not the submitted one');
        assert.equal(context.values.externalAccount, '');
        assert.deepEqual(context.errors, { name: 'bad' });
    });

    await t.test('the edit handler and its failAction render the same context', async t => {
        stub(t, oauth2Apps, {
            async get(id) {
                return { id, provider: 'gmailService', authMethod: 'serviceKey', serviceKey: 'stored' };
            },
            async update() {
                throw new Error('Storage failure');
            }
        });

        const viaHandler = makeToolkit();
        await route('POST', '/admin/config/oauth/edit').handler(makeRequest({ payload: Object.assign(payload(), { app: 'app-1' }) }), viaHandler);
        const viaFail = makeToolkit();
        await route('POST', '/admin/config/oauth/edit').options.validate.failAction(
            makeRequest({ payload: Object.assign(payload(), { app: 'app-1' }) }),
            viaFail,
            {}
        );

        const strip = context => Object.assign({}, context, { errors: undefined });
        assert.deepEqual(strip(viaHandler.answers.views[0].context), strip(viaFail.answers.views[0].context));
    });
});

test('export download', async t => {
    const route = capture('../lib/ui-routes/export-routes');

    await t.test('a read error on an encrypted export ends the response stream', async t => {
        const missing = pathlib.join(os.tmpdir(), `ee-missing-export-${RUN}.ndjson.gz`);
        assert.equal(fs.existsSync(missing), false);
        stub(t, Export, {
            async getFile() {
                return { filePath: missing, filename: 'export.ndjson.gz', isEncrypted: true };
            }
        });

        const res = await route('GET', '/admin/accounts/{account}/export/{exportId}/download').handler(
            makeRequest({ params: { account: 'a', exportId: 'exp_1' } }),
            makeToolkit()
        );

        // Before, the read error was only logged and the decrypt stream was never ended, so hapi
        // held the response open until the socket timed out
        await assert.rejects(
            Promise.race([finished(res.source), new Promise((resolve, reject) => setTimeout(() => reject(new Error('stream left open')), 2000))]),
            err => err.code === 'ENOENT'
        );
    });
});
