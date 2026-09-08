'use strict';

// Which certificate a listener serves, for which name (lib/tls/context.js).
//
// Two bugs live here in equal measure. The first is precedence: the SMTP server and the IMAP proxy
// loaded their environment certificate and then overwrote it with whatever Let's Encrypt had
// provisioned, so an operator who pinned one through EENGINE_SMTP_TLS_CERT was silently served
// something else. The second is that there was only ever one certificate: EmailEngine's admin URL
// and its mail hostname are usually different names, and a client connecting to smtp.example.com
// was offered the admin UI's certificate.
//
// The refresh path matters as much as the initial resolution: the context object is what a running
// listener is handed, and a renewal replaces it in place rather than restarting the worker.

const test = require('node:test');
const assert = require('node:assert').strict;
const tls = require('tls');

process.env.EENGINE_REDIS_PREFIX = 'test_tls_context';
process.env.EENGINE_SECRET = 'tls-context-test-secret';

const { createTlsContext } = require('../lib/tls/context');
const store = require('../lib/tls/store');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { createSelfSignedCertificate } = require('../lib/tls/self-signed');

const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {} };

/**
 * A certificate handler that answers from a fixed map, standing in for @postalsys/certs.
 *
 * @param {Object} records Hostname to `{ cert, privateKey }`
 * @returns {Object} Something with getCertificate()
 */
function fakeCerts(records) {
    return {
        async getCertificate(hostname) {
            const record = records[hostname];
            return record ? Object.assign({ status: 'valid', ca: [] }, record) : false;
        }
    };
}

/**
 * Asks a context which certificate it would serve for a name, the way a TLS handshake does.
 *
 * @param {Object} context Result of createTlsContext()
 * @param {string} servername SNI name
 * @returns {Promise<string>} The subject of the certificate that would be served
 */
async function servedSubject(context, servername) {
    // The SNI callback hands back a SecureContext, which has no readable certificate, so serve it
    // for real and read what the client received. That also proves the context is usable.
    const options = context.options;
    const server = tls.createServer({ cert: options.cert, key: options.key, SNICallback: options.SNICallback }, socket => socket.end('ok'));

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

    try {
        return await new Promise((resolve, reject) => {
            const socket = tls.connect({ port: server.address().port, host: '127.0.0.1', servername, rejectUnauthorized: false }, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve(cert.subject.CN);
            });
            socket.on('error', reject);
        });
    } finally {
        server.close();
    }
}

test('TLS context resolution', async t => {
    t.after(async () => {
        const keys = await redis.keys(`${REDIS_PREFIX}*`);
        if (keys.length) {
            await redis.del(keys);
        }
        redis.quit();
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(async () => {
        const keys = await redis.keys(`${REDIS_PREFIX}*`);
        if (keys.length) {
            await redis.del(keys);
        }
        await settings.set('serviceUrl', 'https://mail.example.com');
        await settings.set('tlsHostnames', null);
        await settings.set('tlsProvisioning', null);
    });

    await t.test('environment material outranks everything else for a name it covers', async () => {
        // The bug this replaces: an explicitly configured certificate was loaded and then
        // overwritten by the automatic one.
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const acme = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const context = await createTlsContext({
            certs: fakeCerts({ 'mail.example.com': acme }),
            logger,
            envMaterial: { cert: env.cert, key: env.privateKey }
        });

        assert.equal(context.source, 'env');
        assert.equal(context.active.fingerprint, env.fingerprint);
    });

    await t.test('environment material does not shadow a name it does not cover', async () => {
        // Applied per name like every other source. A listener told to serve one certificate should
        // still offer a second configured hostname the certificate that actually covers it - and
        // still answer a client that sent no name with the operator's own certificate.
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const env = await createSelfSignedCertificate({ hostnames: ['env.example.com'] });
        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });

        const context = await createTlsContext({
            certs: fakeCerts({ 'smtp.example.com': smtp }),
            logger,
            envMaterial: { cert: env.cert, key: env.privateKey }
        });

        assert.equal(await servedSubject(context, 'smtp.example.com'), 'smtp.example.com');
        assert.equal(await servedSubject(context, undefined), 'env.example.com');
    });

    await t.test('an uploaded certificate outranks the automatic one', async () => {
        const manual = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const acme = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': acme }), logger });

        assert.equal(context.source, 'manual');
        assert.equal(context.active.fingerprint, manual.fingerprint);
    });

    await t.test('an uploaded certificate that does not cover the name is not used for it', async () => {
        // Precedence is per name, not global: a certificate for one hostname says nothing about
        // another, and offering it would fail every handshake for that name.
        const manual = await createSelfSignedCertificate({ hostnames: ['other.example.com'] });
        const acme = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': acme }), logger });

        assert.equal(context.source, 'acme');
    });

    await t.test('the automatic certificate is used when nothing outranks it', async () => {
        const acme = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': acme }), logger });

        assert.equal(context.source, 'acme');
        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
    });

    await t.test('a self-signed certificate is generated when there is nothing at all', async () => {
        // The case that used to refuse to start the listener, after the admin UI had promised for
        // years that a self-signed certificate would be used.
        const context = await createTlsContext({ certs: fakeCerts({}), logger });

        assert.equal(context.source, 'self-signed');
        assert.ok(context.options.cert, 'and the listener has something to serve');
        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
    });

    await t.test('each hostname is served its own certificate', async () => {
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });

        const context = await createTlsContext({
            certs: fakeCerts({ 'mail.example.com': mail, 'smtp.example.com': smtp }),
            logger
        });

        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
        assert.equal(await servedSubject(context, 'smtp.example.com'), 'smtp.example.com');
    });

    await t.test('a client that sends no SNI gets the first hostname', async () => {
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });

        const context = await createTlsContext({
            certs: fakeCerts({ 'mail.example.com': mail, 'smtp.example.com': smtp }),
            logger
        });

        // An SMTP client connecting by IP address sends no server name at all.
        assert.equal(await servedSubject(context, undefined), 'mail.example.com');
    });

    await t.test('a name with no certificate of its own falls back rather than failing', async () => {
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail }), logger });

        // Wrong name, but a completed handshake the operator can diagnose beats a reset connection.
        assert.equal(await servedSubject(context, 'smtp.example.com'), 'mail.example.com');
    });

    await t.test('the source setting decides which stored sources are served', async () => {
        // The setting is the certificate source, so it has to decide what is served and not only
        // whether an order is placed. Picking "self-signed only" while a Let's Encrypt certificate
        // went on being served would be the same class of bug this rework exists to remove.
        const manual = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const acme = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const certs = fakeCerts({ 'mail.example.com': acme });

        await settings.set('tlsProvisioning', 'acme');
        assert.equal((await createTlsContext({ certs, logger })).source, 'manual');

        await settings.set('tlsProvisioning', 'manual');
        assert.equal((await createTlsContext({ certs, logger })).source, 'manual', 'the automatic source is not consulted');

        await settings.set('tlsProvisioning', 'self-signed');
        assert.equal((await createTlsContext({ certs, logger })).source, 'self-signed', 'and neither is the uploaded one');
    });

    await t.test('a mode that admits nothing still serves environment material', async () => {
        // The environment is not a source EmailEngine chose, so no mode declines it.
        await settings.set('tlsProvisioning', 'self-signed');
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

        const context = await createTlsContext({
            certs: fakeCerts({}),
            logger,
            envMaterial: { cert: env.cert, key: env.privateKey }
        });

        assert.equal(context.source, 'env');
    });

    await t.test('refresh() picks up a certificate that arrived after the listener started', async () => {
        // What a renewal does. The listener is not restarted for it, so the context has to report
        // the new material without being rebuilt.
        const records = {};
        const certs = fakeCerts(records);

        const context = await createTlsContext({ certs, logger });
        assert.equal(context.source, 'self-signed');

        const issued = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        records['mail.example.com'] = issued;

        await context.refresh();

        assert.equal(context.source, 'acme');
        assert.equal(context.active.fingerprint, issued.fingerprint);
        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
    });

    await t.test('refresh() does not mistake resolved material for environment material', async () => {
        // The context writes its result into the options a listener holds. Handing that same object
        // back as the environment snapshot made every refresh report "env" and pinned the first
        // certificate forever.
        const issued = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': issued }), logger, envMaterial: {} });

        await context.refresh();
        assert.equal(context.source, 'acme');
    });

    await t.test('a listener with no service URL still gets a certificate', async () => {
        await settings.set('serviceUrl', null);

        const context = await createTlsContext({ certs: fakeCerts({}), logger });

        assert.equal(context.source, 'self-signed');
        assert.equal(await servedSubject(context, 'localhost'), 'localhost');
    });
});
