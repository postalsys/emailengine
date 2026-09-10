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
// The third is choice: environment material was served ahead of everything and could not be chosen
// against, and no listener could be told to present any particular certificate to a client that
// names no host. Which certificate a listener presents by default is a setting now, decided from
// everything the instance holds (lib/tls/catalog.js), with the old precedence as its automatic
// answer.
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
const { fakeCerts, setEnvMaterial, clearTlsEnv, resetTlsSettings } = require('./helpers/tls-fixtures');

const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {} };

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
        clearTlsEnv();
        await resetTlsSettings();
    });

    await t.test('environment material outranks everything else for a name it covers', async () => {
        // The bug this replaces: an explicitly configured certificate was loaded and then
        // overwritten by the automatic one.
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const acme = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        setEnvMaterial('smtp', env);

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': acme }), logger, listener: 'smtp' });

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

        setEnvMaterial('smtp', env);

        const context = await createTlsContext({ certs: fakeCerts({ 'smtp.example.com': smtp }), logger, listener: 'smtp' });

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

        setEnvMaterial('smtp', env);

        const context = await createTlsContext({ certs: fakeCerts({}), logger, listener: 'smtp' });

        assert.equal(context.source, 'env');
        assert.equal(await servedSubject(context, 'smtp.example.com'), 'smtp.example.com');
    });

    await t.test("the listener's environment prefix is where its material is read from, not its options", async () => {
        // A listener's options carry its handshake settings and, once it has started, the material
        // this module resolved for it, merged back into the same object. Reading certificate
        // material off them would take that result for the operator's own on the next refresh -
        // which is what used to pin the first certificate forever - so the material comes from the
        // environment, where every worker reads the same bytes.
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const other = await createSelfSignedCertificate({ hostnames: ['other.example.com'] });
        setEnvMaterial('smtp', env);
        const listenerOptions = { cert: other.cert, key: other.privateKey, minVersion: 'TLSv1.2' };

        const context = await createTlsContext({ certs: fakeCerts({}), logger, listener: 'smtp', listenerOptions });

        assert.equal(context.source, 'env');
        assert.equal(context.active.fingerprint, env.fingerprint);
        assert.equal(context.options.minVersion, 'TLSv1.2', 'the handshake settings are what the options are for');

        // A listener with no material of its own merges the resolved options into the same object,
        // and a refresh still resolves afresh rather than reading that back
        const issued = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const bare = { minVersion: 'TLSv1.2' };
        const resolvedContext = await createTlsContext({
            certs: fakeCerts({ 'mail.example.com': issued }),
            logger,
            listener: 'imapProxy',
            listenerOptions: bare
        });
        Object.assign(bare, resolvedContext.options);

        await resolvedContext.refresh();
        assert.equal(resolvedContext.source, 'acme');
    });

    await t.test('an encrypted environment key is served with its passphrase', async () => {
        // Without the passphrase the context fails to build, and the listener quietly served the
        // self-signed fallback instead of the certificate it was configured with.
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

        setEnvMaterial('smtp', { cert: env.cert, privateKey: encryptKey(env.privateKey, 'hunter2') });
        process.env.EENGINE_SMTP_TLS_PASSPHRASE = 'hunter2';
        const context = await createTlsContext({ certs: fakeCerts({}), logger, listener: 'smtp' });

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

        setEnvMaterial('smtp', { cert: env.cert, privateKey: encryptKey(env.privateKey, 'hunter2') });
        const context = await createTlsContext({ certs: fakeCerts({}), logger: failLogger, listener: 'smtp' });

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

        // And what it is, by the id the settings refer to it by
        assert.equal(active.id, 'acme:mail.example.com');
        assert.equal(active.hostname, 'mail.example.com');
    });

    await t.test('active names the certificate by the id the settings refer to it by', async () => {
        // The page reads this off the listener's state payload and names the certificate from it
        const env = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        setEnvMaterial('smtp', env);

        const context = await createTlsContext({ certs: fakeCerts({}), logger, listener: 'smtp' });

        assert.equal(context.active.id, 'env:smtp');
        assert.equal(context.active.source, 'env');
        assert.equal(context.active.listener, 'smtp');
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

        setEnvMaterial('smtp', env);

        const context = await createTlsContext({ certs: fakeCerts({}), logger, listener: 'smtp' });

        assert.equal(context.source, 'env');
    });

    await t.test('the listener setting picks the certificate presented by default', async () => {
        // The uploaded certificate is for another name entirely, so precedence would never
        // present it to a client that names no host. The setting does.
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['other.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });
        await settings.set('smtpServerTLSCertificate', 'manual');

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail }), logger, listener: 'smtp' });

        assert.equal(await servedSubject(context, undefined), 'other.example.com');
        assert.equal(context.active.id, 'manual');

        // Another listener is not told anything by that setting
        const imapProxy = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail }), logger, listener: 'imapProxy' });
        assert.equal(await servedSubject(imapProxy, undefined), 'mail.example.com');
        assert.equal(imapProxy.active.id, 'acme:mail.example.com');
    });

    await t.test('a chosen default wins for every name it covers, over what precedence would pick', async () => {
        // An uploaded wildcard would outrank the issued certificate for mail.example.com. The
        // operator chose the issued one as the default; asking for that name gets the choice.
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['*.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });
        await settings.set('smtpServerTLSCertificate', 'acme:mail.example.com');

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail }), logger, listener: 'smtp' });

        assert.equal((await servedCertificate(context, 'mail.example.com')).fingerprint, mail.fingerprint);
        assert.equal((await servedCertificate(context, undefined)).fingerprint, mail.fingerprint);
    });

    await t.test('a name the default does not cover is still served its own certificate', async () => {
        // Choosing a default never takes a name's certificate away: a client asking for
        // smtp.example.com is answered with the certificate for smtp.example.com.
        await settings.set('tlsHostnames', ['smtp.example.com']);
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['other.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });
        await settings.set('imapProxyServerTLSCertificate', 'manual');

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail, 'smtp.example.com': smtp }), logger, listener: 'imapProxy' });

        assert.equal(await servedSubject(context, 'smtp.example.com'), 'smtp.example.com');
        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
        assert.equal(await servedSubject(context, undefined), 'other.example.com');
        // A name nothing covers gets the default, as a client that named none does
        assert.equal(await servedSubject(context, 'nothing.example.net'), 'other.example.com');
    });

    await t.test("a listener can be told to present the material from another listener's environment", async () => {
        // The environment is shared by every worker, so EENGINE_API_TLS_CERT is a certificate
        // the SMTP server can present too, once it is asked to.
        const api = await createSelfSignedCertificate({ hostnames: ['admin.example.com'] });
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        setEnvMaterial('api', api);
        await settings.set('smtpServerTLSCertificate', 'env:api');

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail }), logger, listener: 'smtp' });

        assert.equal(await servedSubject(context, undefined), 'admin.example.com');
        assert.equal(context.active.id, 'env:api');
        // and the SMTP server's own name still answers for itself
        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
    });

    await t.test('a chosen certificate that no longer exists is stood in for, and said so', async () => {
        // The upload was removed, or the name was taken off the list. The listener starts on its
        // automatic choice and reports what it was asked for, so the page can say what happened.
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        await settings.set('smtpServerTLSCertificate', 'acme:gone.example.com');

        const warnings = [];
        const context = await createTlsContext({
            certs: fakeCerts({ 'mail.example.com': mail }),
            logger: Object.assign({}, logger, { warn: entry => warnings.push(entry) }),
            listener: 'smtp'
        });

        assert.equal(await servedSubject(context, undefined), 'mail.example.com');
        assert.equal(context.active.id, 'acme:mail.example.com');
        assert.equal(warnings.length, 1);
        assert.equal(warnings[0].requested, 'acme:gone.example.com');
    });

    await t.test("the automatic default is the listener's own environment material even for another name", async () => {
        // EENGINE_SMTP_TLS_CERT for smtp.example.com on an instance whose service URL is
        // mail.example.com: a client that names no host gets what the operator set for this
        // listener, and mail.example.com still answers for itself.
        await settings.set('tlsHostnames', ['smtp.example.com']);
        const env = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });

        setEnvMaterial('smtp', env);

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail }), logger, listener: 'smtp' });

        assert.equal(await servedSubject(context, undefined), 'smtp.example.com');
        assert.equal(await servedSubject(context, 'mail.example.com'), 'mail.example.com');
        assert.equal(context.active.id, 'env:smtp');
    });

    await t.test('refresh() follows a change of the listener setting without a restart', async () => {
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['other.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const context = await createTlsContext({ certs: fakeCerts({ 'mail.example.com': mail }), logger, listener: 'smtp' });
        assert.equal(await servedSubject(context, undefined), 'mail.example.com');

        await settings.set('smtpServerTLSCertificate', 'manual');
        await context.refresh();
        assert.equal(await servedSubject(context, undefined), 'other.example.com');

        await settings.set('smtpServerTLSCertificate', null);
        await context.refresh();
        assert.equal(await servedSubject(context, undefined), 'mail.example.com');
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

    await t.test('a listener with no service URL still gets a certificate', async () => {
        await settings.set('serviceUrl', null);

        const context = await createTlsContext({ certs: fakeCerts({}), logger });

        assert.equal(context.source, 'self-signed');
        assert.equal(await servedSubject(context, 'localhost'), 'localhost');
    });
});
