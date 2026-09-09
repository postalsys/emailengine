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
const crypto = require('crypto');
const tls = require('tls');

process.env.EENGINE_REDIS_PREFIX = 'test_tls_context';
process.env.EENGINE_SECRET = 'tls-context-test-secret';

const { createTlsContext, applyTlsContext } = require('../lib/tls/context');
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
async function servedCertificate(context, servername) {
    // The SNI callback hands back a SecureContext, which has no readable certificate, so serve it
    // for real and read what the client received. That also proves the context is usable.
    const options = context.options;
    const server = tls.createServer({ cert: options.cert, key: options.key, passphrase: options.passphrase, SNICallback: options.SNICallback }, socket =>
        socket.end('ok')
    );

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

    try {
        return await new Promise((resolve, reject) => {
            const socket = tls.connect({ port: server.address().port, host: '127.0.0.1', servername, rejectUnauthorized: false }, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                resolve(cert);
            });
            socket.on('error', reject);
        });
    } finally {
        server.close();
    }
}

async function servedSubject(context, servername) {
    return (await servedCertificate(context, servername)).subject.CN;
}

/**
 * The same key, encrypted the way an operator's key file is.
 *
 * @param {string} privateKey PEM private key
 * @param {string} passphrase Passphrase to protect it with
 * @returns {string} Encrypted PEM private key
 */
function encryptKey(privateKey, passphrase) {
    return crypto.createPrivateKey(privateKey).export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }).toString();
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

    await t.test('environment material does not hide an uploaded certificate for another name', async () => {
        // The uploaded certificate used to be skipped for the whole listener as soon as the
        // environment supplied one, so a second configured hostname was served the fallback while
        // the configuration page listed its certificate as installed.
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const context = await createTlsContext({
            certs: fakeCerts({}),
            logger,
            envMaterial: { cert: env.cert, key: env.privateKey }
        });

        assert.equal(context.source, 'env');
        assert.equal(await servedSubject(context, 'smtp.example.com'), 'smtp.example.com');
    });

    await t.test('the listener options are where the environment material is read from', async () => {
        // The caller merges the resolved options back into the same object, so the material is
        // picked off it here, at entry, rather than being copied out by every listener in turn.
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const listenerOptions = { cert: env.cert, key: env.privateKey, minVersion: 'TLSv1.2' };

        const context = await createTlsContext({ certs: fakeCerts({}), logger, listenerOptions });

        assert.equal(context.source, 'env');
        assert.equal(context.active.fingerprint, env.fingerprint);

        // And it is read once, at entry: a listener with no material of its own merges the resolved
        // options into the same object, which a second reading would take for the operator's own.
        const issued = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const bare = { minVersion: 'TLSv1.2' };
        const resolvedContext = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': issued }), logger, listenerOptions: bare });
        Object.assign(bare, resolvedContext.options);

        await resolvedContext.refresh();
        assert.equal(resolvedContext.source, 'acme');
    });

    await t.test('an encrypted environment key is served with its passphrase', async () => {
        // Without the passphrase the context fails to build, and the listener quietly served the
        // self-signed fallback instead of the certificate it was configured with.
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

        const context = await createTlsContext({
            certs: fakeCerts({}),
            logger,
            envMaterial: { cert: env.cert, key: encryptKey(env.privateKey, 'hunter2'), passphrase: 'hunter2' }
        });

        assert.equal(context.source, 'env');
        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
    });

    await t.test('an encrypted environment key with no passphrase is reported, not served as something else', async () => {
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

        const errors = [];
        const failLogger = Object.assign({}, logger, {
            error(entry) {
                errors.push(entry);
            }
        });

        const context = await createTlsContext({
            certs: fakeCerts({}),
            logger: failLogger,
            envMaterial: { cert: env.cert, key: encryptKey(env.privateKey, 'hunter2') }
        });

        assert.equal(context.source, 'self-signed');
        assert.ok(
            errors.some(entry => entry.source === 'env'),
            'and the operator is told which certificate could not be loaded'
        );
    });

    await t.test('the handshake settings travel with the options a listener installs', async () => {
        // What the listener installs and what the SNI callback hands back are built from one set,
        // so a reload cannot quietly install a context that has lost the operator's settings.
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

        const context = await createTlsContext({
            certs: fakeCerts({ 'mail.example.com': mail, 'smtp.example.com': smtp }),
            logger,
            listenerOptions: { minVersion: 'TLSv1.2', ciphers: 'ECDHE-RSA-AES128-GCM-SHA256', requestCert: true }
        });

        assert.equal(context.options.minVersion, 'TLSv1.2');
        assert.equal(context.options.ciphers, 'ECDHE-RSA-AES128-GCM-SHA256');

        // A listener option, not a context option, and nothing here has any business changing it.
        assert.equal(typeof context.options.requestCert, 'undefined');

        // And the per-name contexts still build and serve with them applied.
        assert.equal(await servedSubject(context, 'smtp.example.com'), 'smtp.example.com');
    });

    await t.test('a reload hands the listener the operator settings along with the certificate', async () => {
        // tls.Server.setSecureContext() replaces the whole context, so a reload that sent only the
        // certificate and key dropped an mTLS `ca` and the configured version bounds at the first
        // renewal - months after the listener had started, with nothing to connect it to.
        const issued = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const clientCa = await createSelfSignedCertificate({ hostnames: ['client.example.com'] });

        const context = await createTlsContext({
            certs: fakeCerts({ 'mail.example.com': issued }),
            logger,
            listenerOptions: { minVersion: 'TLSv1.3', ciphers: 'TLS_AES_256_GCM_SHA384', ca: clientCa.cert }
        });

        let applied = null;
        const result = await applyTlsContext({ context, apply: options => (applied = options), logger });

        assert.equal(result.updated, true);
        assert.equal(applied.minVersion, 'TLSv1.3');
        assert.equal(applied.ciphers, 'TLS_AES_256_GCM_SHA384');
        assert.equal(applied.ca, clientCa.cert);
        assert.ok(applied.cert.includes('BEGIN CERTIFICATE'));
        assert.ok(applied.key);
        assert.equal(typeof applied.SNICallback, 'function');

        // Present even though this material has none: the listener merges these into the options it
        // holds, so a passphrase belonging to material it no longer serves has to be cleared.
        assert.ok('passphrase' in applied);
        assert.equal(applied.passphrase, undefined);
    });

    await t.test('active describes the certificate the way the store does', async () => {
        // The listener state feeds the configuration page, which reports a certificate that is not
        // valid yet and lists the names it covers. Both fields were missing from this shape.
        const issued = await createSelfSignedCertificate({ hostnames: ['mail.example.com', 'smtp.example.com'] });

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': issued }), logger });
        const active = context.active;

        assert.equal(active.source, 'acme');
        assert.equal(active.fingerprint, issued.fingerprint);
        assert.deepEqual(active.altNames, ['mail.example.com', 'smtp.example.com']);
        assert.ok(active.validFrom instanceof Date);
        assert.ok(active.validTo instanceof Date);
        assert.equal(active.selfSigned, true);
        assert.ok(active.serialNumber);
        assert.ok(active.fingerprint256);
        assert.ok(active.subject);
        assert.ok(active.issuer);

        // Nothing here came from the environment, and the certificate page reads that off this list
        assert.deepEqual(active.envHostnames, []);
    });

    await t.test('active names the configured hostnames served from environment material', async () => {
        // The page has no way of knowing: that material is per listener and per process, so a name
        // served only through EENGINE_SMTP_TLS_CERT was painted red as "Missing" while the listener
        // served it perfectly well. The listener is what reports which names it resolved to it.
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });

        const context = await createTlsContext({
            certs: fakeCerts({ 'smtp.example.com': smtp }),
            logger,
            envMaterial: { cert: env.cert, key: env.privateKey }
        });

        // Only the name the environment material answered for; the other one is stored, and the
        // page resolves that for itself.
        assert.deepEqual(context.active.envHostnames, ['mail.example.com']);
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

    await t.test('a name with no certificate of its own is served the self-signed one, which covers it', async () => {
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail }), logger });

        // Not the primary name's certificate: that fails the client's name check just the same,
        // and it is not what the certificates page says the name has. The self-signed fallback
        // covers every configured name, so a client that pinned its fingerprint completes.
        const served = await servedCertificate(context, 'smtp.example.com');
        const stored = await store.peekSelfSignedCertificate();

        assert.equal(served.fingerprint256, stored.fingerprint256, 'the self-signed certificate the page shows');
        assert.ok(store.coversHostname(new crypto.X509Certificate(served.raw), 'smtp.example.com'), 'and it covers the name asked for');

        // The primary name keeps its own certificate, and so does a client that sent no name.
        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
        assert.equal((await servedCertificate(context, undefined)).fingerprint, mail.fingerprint);
    });

    await t.test('no self-signed certificate is generated while every name has one of its own', async () => {
        await settings.set('tlsHostnames', ['smtp.example.com']);

        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });
        await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail, 'smtp.example.com': smtp }), logger });

        assert.equal(await store.peekSelfSignedCertificate(), false, 'nothing for the page to show that no listener serves');
    });

    await t.test('an internationalized name is matched however the listener spells it', async () => {
        // The IMAP proxy's server library decodes the ClientHello name to Unicode before asking for
        // a context; certificates carry the A-label. Both spellings have to find the certificate.
        await settings.set('tlsHostnames', ['xn--pdra-0qa.example.com']);

        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const idn = await createSelfSignedCertificate({ hostnames: ['xn--pdra-0qa.example.com'] });
        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail, 'xn--pdra-0qa.example.com': idn }), logger });

        assert.equal(context.options.SNICallback('xn--pdra-0qa.example.com'), context.options.SNICallback('põdra.example.com'));
        assert.equal(await servedSubject(context, 'xn--pdra-0qa.example.com'), 'xn--pdra-0qa.example.com');
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
