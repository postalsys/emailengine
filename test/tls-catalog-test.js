'use strict';

// Every certificate the instance holds, under one id each, and what a listener makes of the list
// (lib/tls/catalog.js).
//
// Material from EENGINE_SMTP_TLS_* used to be invisible as a certificate: loaded by one listener,
// served ahead of everything, described on the page only second-hand from what that listener
// reported. It could not be chosen for another listener, and nothing could be chosen over it.
// This is the module that gives it a row and an id like the uploaded, issued and self-signed
// ones, and decides a listener's default and per-name answers from the whole list - once, for the
// listener and the page alike.

const test = require('node:test');
const assert = require('node:assert').strict;

process.env.EENGINE_REDIS_PREFIX = 'test_tls_catalog';
process.env.EENGINE_SECRET = 'tls-catalog-test-secret';

const catalog = require('../lib/tls/catalog');
const { TLS_CERTIFICATE_SETTINGS } = require('../lib/tls/listeners');
const store = require('../lib/tls/store');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { createSelfSignedCertificate } = require('../lib/tls/self-signed');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { fakeCerts, setEnvMaterial, clearTlsEnv, resetTlsSettings } = require('./helpers/tls-fixtures');

const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {} };

// EC keys: nothing here depends on the key type, and an RSA keypair costs a hundred times more
const pair = hostnames => createSelfSignedCertificate({ hostnames, keyType: 'ec' });

async function reset() {
    clearTlsEnv();
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length) {
        await redis.del(keys);
    }
    await resetTlsSettings();
}

registerRedisTeardown(redis, reset);

test('certificate ids', async t => {
    await t.test('every source has an id, and the id names what it is made of', () => {
        assert.equal(catalog.certificateId({ source: 'env', listener: 'smtp' }), 'env:smtp');
        assert.equal(catalog.certificateId({ source: 'manual' }), 'manual');
        assert.equal(catalog.certificateId({ source: 'acme', hostname: 'smtp.example.com' }), 'acme:smtp.example.com');
        assert.equal(catalog.certificateId({ source: 'self-signed' }), 'self-signed');
    });

    await t.test('material that cannot be named has no id', () => {
        // Issued material without the name it was issued for, and environment material with no
        // listener, are the two shapes that cannot be stored in a setting
        assert.equal(catalog.certificateId({ source: 'acme' }), null);
        assert.equal(catalog.certificateId({ source: 'env' }), null);
        assert.equal(catalog.certificateId(false), null);
    });

    await t.test('an id parses back to its parts, and nothing else parses', () => {
        assert.deepEqual(catalog.parseCertificateId('env:imapProxy'), { source: 'env', listener: 'imapProxy' });
        assert.deepEqual(catalog.parseCertificateId('acme:smtp.example.com'), { source: 'acme', hostname: 'smtp.example.com' });
        assert.deepEqual(catalog.parseCertificateId('manual'), { source: 'manual' });
        // Ids are spelled the way the stores spell a hostname, and the settings schema refuses
        // anything else, so nothing folds one here either
        assert.equal(catalog.parseCertificateId('acme:SMTP.Example.com'), null);
        assert.equal(catalog.parseCertificateId('auto'), null);
        assert.equal(catalog.parseCertificateId('env:nginx'), null);
        assert.equal(catalog.parseCertificateId('acme:'), null);
        assert.equal(catalog.parseCertificateId(''), null);
    });

    await t.test('a setting reads as an id or as auto, never as anything in between', () => {
        assert.equal(catalog.requestedCertificate(null), 'auto');
        assert.equal(catalog.requestedCertificate(''), 'auto');
        assert.equal(catalog.requestedCertificate('auto'), 'auto');
        assert.equal(catalog.requestedCertificate(' manual '), 'manual');
        // A value the schema would refuse, reached through an older store: the listener does not
        // die on it, it decides for itself
        assert.equal(catalog.requestedCertificate('whatever'), 'auto');
    });

    await t.test('the three settings are one per listener', () => {
        assert.deepEqual(TLS_CERTIFICATE_SETTINGS, ['apiTLSCertificate', 'smtpServerTLSCertificate', 'imapProxyServerTLSCertificate']);
    });
});

test('the certificate list', async t => {
    t.beforeEach(reset);

    await t.test('lists the uploaded certificate, each issued one, and the fallback, in precedence order', async () => {
        const manual = await pair(['*.example.com']);
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });
        const mail = await pair(['mail.example.com']);
        const smtp = await pair(['smtp.example.com']);

        const entries = await catalog.listCertificates({
            certs: fakeCerts({ 'mail.example.com': mail, 'smtp.example.com': smtp }),
            hostnames: ['mail.example.com', 'smtp.example.com', 'imap.example.com'],
            logger
        });

        assert.deepEqual(
            entries.map(entry => entry.id),
            ['manual', 'acme:mail.example.com', 'acme:smtp.example.com', 'self-signed']
        );
        assert.equal(entries[0].label, 'Uploaded certificate');
        assert.equal(entries[1].label, "Let's Encrypt for mail.example.com");
        assert.equal(entries[1].hostname, 'mail.example.com');
        assert.equal(entries[1].material.hostname, 'mail.example.com', 'issued material carries the name its id is made of');
        assert.ok(entries[1].x509, 'parsed once, for the name matching every reader does');

        // Nothing has generated the fallback, and listing must not either: it is listed as a
        // choice a listener can be given, and generated when one is
        assert.equal(entries[3].label, 'Self-signed fallback');
        assert.equal(entries[3].material, false);
        assert.equal(catalog.isSelectable(entries[3]), true);
        assert.equal(await redis.hget(store.TLS_KEY, store.SELF_SIGNED_FIELD), null);
    });

    await t.test('lists the material a listener reads from its environment, for every listener', async () => {
        // Read from the shared environment rather than from the listener that loaded it, so every
        // worker lists the same bytes - which is what lets one listener be told to present another's
        const api = await pair(['admin.example.com']);
        const smtp = await pair(['smtp.example.com']);
        setEnvMaterial('api', api);
        setEnvMaterial('smtp', smtp);

        const entries = await catalog.listCertificates({ certs: fakeCerts({}), hostnames: ['mail.example.com'], logger });

        assert.deepEqual(
            entries.map(entry => entry.id),
            ['env:api', 'env:smtp', 'self-signed']
        );
        assert.equal(entries[0].label, 'Environment (Admin UI and API)');
        assert.match(entries[0].detail, /EENGINE_API_TLS_/);
        assert.deepEqual(entries[0].material.altNames, ['admin.example.com']);
        assert.equal(entries[1].material.listener, 'smtp');
        assert.equal(entries[1].material.privateKey, smtp.privateKey, 'served straight from the environment, so the key is what was set');
    });

    await t.test('environment material that does not parse is reported and not listed', async () => {
        process.env.EENGINE_SMTP_TLS_CERT = 'not a certificate';
        process.env.EENGINE_SMTP_TLS_KEY = 'nor a key';

        const errors = [];
        const entries = await catalog.listCertificates({
            certs: fakeCerts({}),
            hostnames: [],
            logger: Object.assign({}, logger, { error: entry => errors.push(entry) })
        });

        assert.deepEqual(
            entries.map(entry => entry.id),
            ['self-signed']
        );
        assert.equal(errors.length, 1);
        assert.equal(errors[0].listener, 'smtp');
        assert.equal(catalog.envMaterialFor('nginx'), false);
    });

    await t.test('an uploaded key stays out of a listing that did not ask for it', async () => {
        const manual = await pair(['mail.example.com']);
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const peeked = await catalog.listCertificates({ certs: fakeCerts({}), hostnames: [], logger });
        assert.equal(peeked[0].id, 'manual');
        assert.equal(peeked[0].material.privateKey, undefined);

        const loaded = await catalog.listCertificates({ certs: fakeCerts({}), hostnames: [], logger, withPrivateKey: true });
        assert.ok(loaded[0].material.privateKey);
    });

    await t.test('the source setting is a filter over the list, and environment material is per listener', async () => {
        const manual = await pair(['*.example.com']);
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });
        const mail = await pair(['mail.example.com']);
        const smtp = await pair(['smtp.example.com']);
        setEnvMaterial('smtp', smtp);

        const entries = await catalog.listCertificates({ certs: fakeCerts({ 'mail.example.com': mail }), hostnames: ['mail.example.com'], logger });

        const ids = list => list.map(entry => entry.id);
        assert.deepEqual(ids(catalog.admittedFor(entries, { listener: 'smtp', sources: catalog.sourcesFor('acme') })), [
            'env:smtp',
            'manual',
            'acme:mail.example.com'
        ]);
        assert.deepEqual(ids(catalog.admittedFor(entries, { listener: 'api', sources: catalog.sourcesFor('acme') })), ['manual', 'acme:mail.example.com']);
        assert.deepEqual(ids(catalog.admittedFor(entries, { listener: null, sources: catalog.sourcesFor('manual') })), ['manual']);
        // The self-signed entry is never admitted for a name here: it is what a view adds for a
        // name nothing else covers
        assert.deepEqual(ids(catalog.admittedFor(entries, { listener: 'smtp', sources: catalog.sourcesFor('self-signed') })), ['env:smtp']);
    });
});

test('the default certificate', async t => {
    let entries;
    let byId;

    t.before(async () => {
        const [wildcard, mail, smtp, env] = await Promise.all([
            pair(['*.example.com']),
            pair(['mail.example.com']),
            pair(['smtp.example.com']),
            pair(['smtp.example.com'])
        ]);
        const entry = (fields, material) =>
            Object.assign(
                { id: catalog.certificateId(fields), material: Object.assign({}, material, fields), x509: store.parseCertificate(material.cert) },
                fields,
                catalog.describeEntry(fields)
            );
        entries = [
            entry({ source: 'env', listener: 'smtp' }, env),
            entry({ source: 'manual' }, wildcard),
            entry({ source: 'acme', hostname: 'mail.example.com' }, mail),
            entry({ source: 'acme', hostname: 'smtp.example.com' }, smtp),
            Object.assign({ id: 'self-signed', material: false, x509: false, source: 'self-signed' }, catalog.describeEntry({ source: 'self-signed' }))
        ];
        byId = id => entries.find(item => item.id === id);
    });

    const resolve = opts =>
        catalog.resolveDefaultCertificate(Object.assign({ catalog: entries, entries: [byId('acme:mail.example.com')], primary: 'mail.example.com' }, opts));

    await t.test('a chosen certificate is presented as long as it exists', () => {
        const choice = resolve({ listener: 'api', requested: 'manual' });
        assert.equal(choice.entry, byId('manual'));
        assert.equal(choice.selection, 'selected');
    });

    await t.test('a chosen certificate outranks the environment material of the listener', () => {
        // The environment is the automatic choice, not the only one: an operator who picked
        // something else on the page meant it
        const choice = resolve({ listener: 'smtp', requested: 'acme:mail.example.com' });
        assert.equal(choice.entry, byId('acme:mail.example.com'));
        assert.equal(choice.selection, 'selected');
    });

    await t.test('a chosen self-signed fallback is honored before it has been generated', () => {
        const choice = resolve({ listener: 'api', requested: 'self-signed' });
        assert.equal(choice.entry, byId('self-signed'));
        assert.equal(choice.selection, 'selected');
        assert.equal(choice.entry.material, false, 'the listener generates it');
    });

    await t.test("the automatic choice is the listener's own environment material, whatever it covers", () => {
        // EENGINE_SMTP_TLS_CERT for smtp.example.com on an instance whose service URL is
        // mail.example.com: the operator meant the SMTP server to present it, so a client that
        // names no host gets it - not the admin UI's certificate
        const choice = resolve({ listener: 'smtp', requested: null });
        assert.equal(choice.entry, byId('env:smtp'));
        assert.equal(choice.selection, 'auto');
    });

    await t.test('without environment material the automatic choice is the certificate for the primary name', () => {
        // Listed the other way round: it is the name that decides, not the position
        const choice = resolve({ listener: 'api', requested: 'auto', entries: [byId('acme:smtp.example.com'), byId('acme:mail.example.com')] });
        assert.equal(choice.entry, byId('acme:mail.example.com'));
        assert.equal(choice.selection, 'auto');
    });

    await t.test('then any certificate answering a name, then the fallback', () => {
        const some = resolve({ listener: 'api', requested: 'auto', entries: [byId('acme:smtp.example.com')] });
        assert.equal(some.entry, byId('acme:smtp.example.com'));

        const none = resolve({ listener: 'api', requested: 'auto', entries: [] });
        assert.equal(none.entry, byId('self-signed'));
        assert.equal(none.selection, 'auto');
    });

    await t.test('a chosen certificate that no longer exists is stood in for, and reported', () => {
        // The uploaded certificate was removed, or the name whose certificate was chosen was
        // taken off the list. The listener does not go down, and the page can say what happened
        const choice = resolve({ listener: 'api', requested: 'acme:gone.example.com' });
        assert.equal(choice.selection, 'missing');
        assert.equal(choice.requested, 'acme:gone.example.com');
        assert.equal(choice.entry, byId('acme:mail.example.com'));
    });
});

test('what a listener makes of the list', async t => {
    t.beforeEach(reset);

    const view = async (opts, records) => {
        const hostnames = opts.hostnames || ['mail.example.com', 'smtp.example.com'];
        const list = await catalog.listCertificates({ certs: fakeCerts(records || {}), hostnames, logger });
        return catalog.listenerView(Object.assign({ catalog: list, hostnames, sources: catalog.sourcesFor(opts.mode || 'acme') }, opts));
    };

    await t.test('each name is answered by the first admitted entry covering it', async () => {
        const [mail, smtp] = await Promise.all([pair(['mail.example.com']), pair(['smtp.example.com'])]);
        const result = await view({ listener: 'smtp' }, { 'mail.example.com': mail, 'smtp.example.com': smtp });

        assert.deepEqual(
            result.entries.map(entry => entry.id),
            ['acme:mail.example.com', 'acme:smtp.example.com']
        );
        assert.equal(result.fallback.id, 'acme:mail.example.com');
        assert.equal(result.selection, 'auto');
        assert.deepEqual(result.uncovered, []);
        assert.equal(result.needsSelfSigned, false, 'every name has a certificate, so nothing needs generating');

        assert.equal(catalog.entryForName('smtp.example.com', result).id, 'acme:smtp.example.com');
        assert.equal(catalog.entryForName(undefined, result).id, 'acme:mail.example.com');
        assert.equal(catalog.entryForName('nothing.example.net', result).id, 'acme:mail.example.com');
    });

    await t.test('the default wins for every name it covers, and the other names keep their own', async () => {
        // An uploaded wildcard outranks the issued certificate for a name. The operator chose the
        // issued one as the default; asking for that name gets the choice, the other name gets
        // the wildcard as precedence says.
        const [mail, smtp, wildcard] = await Promise.all([pair(['mail.example.com']), pair(['smtp.example.com']), pair(['*.example.com'])]);
        await store.setManualCertificate({ cert: wildcard.cert, privateKey: wildcard.privateKey });

        const result = await view({ listener: 'api', requested: 'acme:mail.example.com' }, { 'mail.example.com': mail, 'smtp.example.com': smtp });

        assert.equal(result.selection, 'selected');
        assert.equal(catalog.entryForName('mail.example.com', result).id, 'acme:mail.example.com');
        assert.equal(catalog.entryForName('smtp.example.com', result).id, 'manual');
        assert.equal(catalog.entryForName(undefined, result).id, 'acme:mail.example.com');
    });

    await t.test('a name nothing covers gets the self-signed fallback, which is then needed', async () => {
        const mail = await pair(['mail.example.com']);
        const result = await view({ listener: 'api' }, { 'mail.example.com': mail });

        assert.deepEqual(result.uncovered, ['smtp.example.com']);
        assert.equal(result.needsSelfSigned, true);
        assert.deepEqual(
            result.entries.map(entry => entry.id),
            ['acme:mail.example.com', 'self-signed']
        );
        // Not generated by looking: the listener does that, the page shows it as not yet there
        assert.equal(result.entries[1].material, false);
    });

    await t.test("a listener's own environment material answers its names first and is its default", async () => {
        const [mail, env] = await Promise.all([pair(['mail.example.com']), pair(['smtp.example.com'])]);
        setEnvMaterial('smtp', env);

        const smtp = await view({ listener: 'smtp' }, { 'mail.example.com': mail });
        assert.equal(smtp.fallback.id, 'env:smtp');
        assert.equal(catalog.entryForName('smtp.example.com', smtp).id, 'env:smtp');
        assert.equal(catalog.entryForName('mail.example.com', smtp).id, 'acme:mail.example.com');
        assert.equal(smtp.needsSelfSigned, false);

        // Another listener is not told anything by it, so for that one the name is uncovered
        const api = await view({ listener: 'api' }, { 'mail.example.com': mail });
        assert.equal(api.fallback.id, 'acme:mail.example.com');
        assert.deepEqual(api.uncovered, ['smtp.example.com']);
    });

    await t.test('a chosen default is presented whatever the source setting admits', async () => {
        const manual = await pair(['other.example.com']);
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const result = await view({ listener: 'imapProxy', requested: 'manual', mode: 'self-signed' });
        assert.equal(result.fallback.id, 'manual');
        assert.equal(result.selection, 'selected');
        // and the names it does not cover are the fallback's, since the mode admits nothing else
        assert.deepEqual(result.uncovered, ['mail.example.com', 'smtp.example.com']);
    });

    await t.test('a chosen certificate that is gone leaves the view on the automatic choice, and says so', async () => {
        const mail = await pair(['mail.example.com']);
        const result = await view({ listener: 'smtp', requested: 'acme:gone.example.com' }, { 'mail.example.com': mail });

        assert.equal(result.selection, 'missing');
        assert.equal(result.requested, 'acme:gone.example.com');
        assert.equal(result.fallback.id, 'acme:mail.example.com');
    });
});
