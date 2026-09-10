'use strict';

// The certificate model the admin UI renders (lib/tls/status.js).
//
// This replaces a single badge next to a checkbox whose four states included one - "Self-signed" -
// that described something the product did not do. The badge could not say what a listener was
// serving, when the certificate expired, where it came from, or why the last order failed, and the
// page that showed it provisioned a certificate as a side effect of being rendered.

const test = require('node:test');
const assert = require('node:assert').strict;

process.env.EENGINE_REDIS_PREFIX = 'test_tls_status';
process.env.EENGINE_SECRET = 'tls-status-test-secret';

const status = require('../lib/tls/status');
const store = require('../lib/tls/store');
const provision = require('../lib/tls/provision');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { createSelfSignedCertificate } = require('../lib/tls/self-signed');
const { fakeCerts, setEnvMaterial, clearTlsEnv, resetTlsSettings } = require('./helpers/tls-fixtures');

const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {} };

const DAY = 24 * 3600 * 1000;

function certificate(overrides) {
    return Object.assign(
        {
            source: 'acme',
            fingerprint: 'AA:BB',
            validFrom: new Date(Date.now() - DAY),
            validTo: new Date(Date.now() + 60 * DAY)
        },
        overrides || {}
    );
}

test('certificateLabel()', async t => {
    await t.test('reports a healthy certificate as valid', () => {
        assert.deepEqual(status.certificateLabel(certificate()), { type: 'success', text: 'Valid', title: 'AA:BB' });
    });

    await t.test('names the environment as a source of its own', () => {
        // Otherwise an operator who supplied the certificate through EENGINE_SMTP_TLS_CERT sees a
        // page that credits Let's Encrypt for it.
        assert.equal(status.certificateLabel(certificate({ source: 'env' })).text, 'From environment');
    });

    await t.test('warns about a self-signed certificate without calling it broken', () => {
        const label = status.certificateLabel(certificate({ source: 'self-signed' }));

        assert.equal(label.type, 'warning');
        assert.equal(label.text, 'Self-signed');
        assert.match(label.title, /can not verify/);
    });

    await t.test('a self-signed certificate nothing serves is a note, not a warning', () => {
        // Severity follows consequence: until a listener presents it to a client, the fallback
        // is a fact about the instance rather than something to fix.
        const label = status.certificateLabel(certificate({ source: 'self-signed' }), null, { served: false });

        assert.equal(label.type, 'neutral');
        assert.equal(label.text, 'Self-signed');
        assert.match(label.title, /no listener is serving it/);
    });

    await t.test('counts down the last two weeks', () => {
        const label = status.certificateLabel(certificate({ validTo: new Date(Date.now() + 3 * DAY) }));

        assert.equal(label.type, 'warning');
        assert.equal(label.text, 'Expires in 3 days');

        assert.equal(status.certificateLabel(certificate({ validTo: new Date(Date.now() + DAY + 3600 * 1000) })).text, 'Expires in 1 day');
        assert.equal(status.certificateLabel(certificate({ validTo: new Date(Date.now() + 3600 * 1000) })).text, 'Expires today');
    });

    await t.test('reports an expired or not-yet-valid certificate', () => {
        // Both fail a handshake identically, and a clock that is wrong produces the second one.
        assert.equal(status.certificateLabel(certificate({ validTo: new Date(Date.now() - DAY) })).type, 'error');
        assert.equal(status.certificateLabel(certificate({ validFrom: new Date(Date.now() + DAY) })).text, 'Not yet valid');
    });

    await t.test('carries the reason an order failed', () => {
        const label = status.certificateLabel(false, { state: 'failed', message: 'DNS problem: NXDOMAIN' });

        assert.equal(label.type, 'error');
        assert.equal(label.title, 'DNS problem: NXDOMAIN');
    });

    await t.test('warns about a failed renewal without calling the certificate broken', () => {
        // The certificate is still usable and still being served, so every other check would call
        // it Valid - which is the failure mode: a green badge until the day it expires.
        const label = status.certificateLabel(certificate(), { state: 'renewalFailed', message: 'Could not renew, still serving the current one' });

        assert.equal(label.type, 'warning');
        assert.equal(label.text, 'Renewal failed');
        assert.match(label.title, /still serving the current one/);
    });

    await t.test('an expired certificate outranks the failed renewal that explains it', () => {
        const label = status.certificateLabel(certificate({ validTo: new Date(Date.now() - DAY) }), { state: 'renewalFailed', message: 'Could not renew' });

        assert.equal(label.type, 'error');
        assert.equal(label.text, 'Expired');
    });

    await t.test('shows an order in flight', () => {
        assert.equal(status.certificateLabel(false, { state: 'ordering', message: 'Requesting' }).text, 'Requesting');
    });

    await t.test('a name without a certificate is not an error', () => {
        // A listener with TLS on always has the self-signed fallback, so "missing" is not a
        // state a name can be in. What it is depends on what asking for one would do.
        const requestable = status.certificateLabel(false, null, { canRequest: true });
        assert.equal(requestable.type, 'neutral');
        assert.equal(requestable.text, 'Not requested');

        const fallback = status.certificateLabel(false, null, { canRequest: false });
        assert.equal(fallback.type, 'neutral');
        assert.equal(fallback.text, 'Self-signed');
        assert.match(fallback.title, /first time a listener needs one/);
    });
});

test('summarizeLabels()', async t => {
    await t.test('is "TLS off" when no listener reports a certificate', () => {
        assert.equal(status.summarizeLabels([]).text, 'TLS off');
        assert.equal(status.summarizeLabels([null, null, null]).type, 'neutral');
    });

    await t.test('picks the worst of what the listeners serve', () => {
        const valid = status.certificateLabel(certificate());
        const selfSigned = status.certificateLabel(certificate({ source: 'self-signed' }));
        const failed = status.certificateLabel(false, { state: 'failed', message: 'NXDOMAIN' });

        assert.equal(status.summarizeLabels([valid, null]).text, 'Valid');
        assert.equal(status.summarizeLabels([valid, selfSigned]).text, 'Self-signed');
        assert.equal(status.summarizeLabels([selfSigned, failed, valid]).text, 'Failed');
    });
});

test('publicView()', async t => {
    await t.test('never carries the private key', async () => {
        const material = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const view = status.publicView(Object.assign({ source: 'manual' }, store.describeCertificate(material.cert), material));

        assert.equal(view.privateKey, undefined);
        assert.equal(view.cert, undefined);
        assert.equal(view.sourceLabel, 'Uploaded');
        assert.deepEqual(view.altNames, ['mail.example.com']);
        assert.equal(typeof view.validToIso, 'string');
        assert.equal(status.publicView(false), false);
    });
});

test('listenerCertificateSummary()', async t => {
    // What the SMTP and IMAP proxy pages show next to their own TLS checkbox. They read the
    // listener's own report, which is JSON out of a Redis hash: every date in it is a string.
    const reported = source => ({
        source,
        fingerprint: 'AA:BB',
        validFrom: new Date(Date.now() - DAY).toISOString(),
        validTo: new Date(Date.now() + 60 * DAY).toISOString()
    });

    await t.test('carries the provisioning state the report cannot know about', () => {
        // Without it these pages could only ever say "Valid", including under a renewal that had
        // been failing for weeks - which is exactly the failure the badge exists to show.
        assert.equal(status.listenerCertificateSummary({ reported: reported('acme'), hostname: 'mail.example.com' }).label.text, 'Valid');

        const summary = status.listenerCertificateSummary({
            reported: reported('acme'),
            hostname: 'mail.example.com',
            status: { state: 'renewalFailed', message: 'Could not renew, still serving the current one' }
        });

        assert.equal(summary.label.type, 'warning');
        assert.equal(summary.label.text, 'Renewal failed');
        assert.equal(summary.hostname, 'mail.example.com');
        assert.equal(summary.certificate.sourceLabel, "Let's Encrypt");
    });

    await t.test('reports an order in flight rather than the certificate it will replace', () => {
        const summary = status.listenerCertificateSummary({
            reported: reported('self-signed'),
            hostname: 'mail.example.com',
            status: { state: 'ordering', message: 'Requesting a certificate for mail.example.com' }
        });

        assert.equal(summary.label.text, 'Requesting');
    });

    await t.test('rehydrates both dates, so a clock problem is still visible', () => {
        const notYet = Object.assign(reported('env'), { validFrom: new Date(Date.now() + DAY).toISOString() });

        assert.equal(status.listenerCertificateSummary({ reported: notYet, hostname: 'mail.example.com' }).label.text, 'Not yet valid');
    });

    await t.test('has nothing to say about a listener that has not reported', () => {
        // The empty shape rather than nothing at all, so the page has one thing to render and one
        // field to test for when it falls back to the stored model.
        assert.deepEqual(status.listenerCertificateSummary({ reported: null, hostname: 'mail.example.com' }), {
            hostname: 'mail.example.com',
            certificate: null,
            label: null
        });
    });

    await t.test('a listener report only counts while the listener is listening', () => {
        // The state record keeps the payload of the last transition that carried one, and a crash
        // carries none: a dead listener kept reporting the certificate it served before it died.
        const tls = reported('acme');

        assert.deepEqual(status.reportedListenerTls({ state: 'listening', payload: { tls } }), tls);

        for (const state of ['exited', 'spawning', 'initializing', 'failed', 'disabled', 'suspended']) {
            assert.equal(status.reportedListenerTls({ state, payload: { tls } }), null, state);
        }

        assert.equal(status.reportedListenerTls({ state: 'listening', payload: {} }), null, 'listening without TLS');
        assert.equal(status.reportedListenerTls({ state: 'listening' }), null, 'no payload at all');
        assert.equal(status.reportedListenerTls(null), null);
    });
});

test('buildCertificateStatus()', async t => {
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

    await t.test('describes every configured hostname', async () => {
        await settings.set('tlsHostnames', ['smtp.example.com', '192.0.2.10']);

        const material = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const certs = {
            async getCertificate(hostname) {
                return hostname === 'mail.example.com' ? { status: 'valid', cert: material.cert, privateKey: material.privateKey, ca: [] } : false;
            }
        };

        const model = await status.buildCertificateStatus({ certs });

        assert.deepEqual(
            model.certificates.map(entry => entry.hostname),
            ['mail.example.com', 'smtp.example.com', '192.0.2.10']
        );
        assert.equal(model.certificates[0].certificate.source, 'acme');
        assert.equal(model.certificates[1].certificate, false);

        // An address literal cannot be validated by a CA, and saying so is more useful than
        // offering a button that will always fail.
        assert.equal(model.certificates[0].acmeEligible, true);
        assert.equal(model.certificates[2].acmeEligible, false);

        // The Service URL's name is marked, because it is the one row the page cannot remove
        assert.equal(model.certificates[0].isServiceHostname, true);
        assert.equal(model.certificates[1].isServiceHostname, false);

        // Nothing is serving TLS, so nothing on this page is red: the names without a
        // certificate read as not requested (public) or as the fallback (an address literal)
        assert.equal(model.served, false);
        assert.equal(model.certificates[1].label.type, 'neutral');
        assert.equal(model.certificates[1].label.text, 'Not requested');
        assert.equal(model.certificates[2].label.text, 'Self-signed');
        assert.equal(model.certificates[2].label.type, 'neutral');

        // And the one action worth offering is offered for the one name it would help
        assert.equal(model.certificates[0].wanted, false, 'a valid certificate is left to the reconciler');
        assert.equal(model.certificates[1].wanted, true);
        assert.equal(model.certificates[2].wanted, false);
        assert.equal(model.anyWanted, true);
    });

    await t.test('a listener report is what turns the fallback into a warning', async () => {
        await store.getSelfSignedCertificate(['mail.example.com'], logger);

        const certs = {
            async getCertificate() {
                return false;
            }
        };

        const quiet = await status.buildCertificateStatus({ certs });
        assert.equal(quiet.certificates[0].certificate.source, 'self-signed');
        assert.equal(quiet.certificates[0].label.type, 'neutral');

        // The same instance with the SMTP server presenting that certificate to clients, which the
        // page learns from the listener reports and hands over as one flag
        const serving = await status.buildCertificateStatus({ certs, served: Promise.resolve(true) });
        assert.equal(serving.served, true);
        assert.equal(serving.certificates[0].label.type, 'warning');
        assert.equal(serving.certificates[0].wanted, true, "and asking Let's Encrypt is the thing to do");
    });

    await t.test('does not provision anything', async () => {
        // Rendering a page used to be able to start an ACME order. It is the reason a checkbox
        // ended up holding an HTTP request open for the length of one.
        const calls = [];
        const certs = {
            async getCertificate(hostname, skipAcquire) {
                calls.push(skipAcquire);
                return false;
            }
        };

        await status.buildCertificateStatus({ certs });

        assert.ok(calls.length);
        assert.ok(
            calls.every(skipAcquire => skipAcquire === true),
            'every read asks the store, never the certificate authority'
        );

        // And no self-signed certificate is minted as a side effect of looking at the page.
        assert.equal(await redis.hget(store.TLS_KEY, store.SELF_SIGNED_FIELD), null);
    });

    await t.test('prefers an uploaded certificate that covers the name', async () => {
        const manual = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const acme = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const certs = {
            async getCertificate() {
                return { status: 'valid', cert: acme.cert, privateKey: acme.privateKey, ca: [] };
            }
        };

        const model = await status.buildCertificateStatus({ certs });

        assert.equal(model.certificates[0].certificate.source, 'manual');
        assert.equal(model.certificates[0].certificate.fingerprint, manual.fingerprint);
        assert.equal(model.certificates[0].certificate.label, 'Uploaded certificate');
        assert.equal(model.manual, true);
        assert.equal(model.catalog.find(entry => entry.id === 'manual').certificate.fingerprint, manual.fingerprint);
    });

    await t.test('reports the self-signed fallback as the certificate for the names it covers', async () => {
        await store.getSelfSignedCertificate(['mail.example.com'], logger);

        const certs = {
            async getCertificate() {
                return false;
            }
        };

        const model = await status.buildCertificateStatus({ certs });

        assert.equal(model.certificates[0].certificate.source, 'self-signed');
        assert.equal(model.certificates[0].label.text, 'Self-signed');
        assert.ok(model.selfSigned.fingerprint);
    });

    await t.test('carries the recorded provisioning state', async () => {
        await provision.setProvisioningStatus(logger, 'mail.example.com', { state: 'failed', message: 'Connection refused' });

        const certs = {
            async getCertificate() {
                return false;
            }
        };

        const model = await status.buildCertificateStatus({ certs });

        assert.equal(model.certificates[0].status.state, 'failed');
        assert.equal(model.certificates[0].label.title, 'Connection refused');
        // The line the page shows under the name, coloured the way the badge is
        assert.deepEqual(model.certificates[0].reason, { variant: 'error', message: 'Connection refused' });
    });

    await t.test('a successful order leaves no line under the name', async () => {
        // The row already says everything the recorded message would
        await provision.setProvisioningStatus(logger, 'mail.example.com', { state: 'valid', message: 'Certificate issued' });

        const model = await status.buildCertificateStatus({
            certs: {
                async getCertificate() {
                    return false;
                }
            }
        });

        assert.equal(model.certificates[0].reason, null);
    });

    await t.test('an order in flight is not offered a second request', async () => {
        await provision.setProvisioningStatus(logger, 'mail.example.com', { state: 'ordering', message: 'Requesting a certificate' });

        const model = await status.buildCertificateStatus({
            certs: {
                async getCertificate() {
                    return false;
                }
            }
        });

        assert.equal(model.certificates[0].label.text, 'Requesting');
        assert.equal(model.certificates[0].wanted, false);
        assert.equal(model.certificates[0].reason.variant, 'info');
    });

    await t.test('renders a failed renewal as a warning, not as a failure', async () => {
        // The alert and the badge come from the same state, so a renewal that failed under a
        // certificate that still works must not be painted the way a missing certificate is.
        await provision.setProvisioningStatus(logger, 'mail.example.com', { state: 'renewalFailed', message: 'Could not renew the certificate' });

        const model = await status.buildCertificateStatus({
            certs: {
                async getCertificate() {
                    return false;
                }
            }
        });

        assert.equal(model.certificates[0].reason.variant, 'warning');
    });

    await t.test('lists every certificate the instance holds, with the listeners presenting it', async () => {
        await settings.set('tlsHostnames', ['smtp.example.com']);
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['other.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });

        const certs = fakeCerts({ 'mail.example.com': mail });

        const model = await status.buildCertificateStatus({ certs });

        assert.deepEqual(
            model.catalog.map(entry => entry.id),
            ['manual', 'acme:mail.example.com', 'self-signed']
        );
        assert.equal(model.catalog[0].label, 'Uploaded certificate');
        assert.equal(model.catalog[0].certificate.privateKey, undefined, 'the page never carries a key');
        assert.deepEqual(model.catalog[0].usedBy, [], 'nothing presents a certificate for another name by default');

        // Every listener decides automatically, and the answer is the primary name's certificate
        assert.deepEqual(
            model.catalog[1].usedBy.map(entry => [entry.key, entry.label]),
            [
                ['api', 'Admin UI and API (automatic)'],
                ['smtp', 'SMTP server (automatic)'],
                ['imapProxy', 'IMAP proxy (automatic)']
            ]
        );

        // The fallback is listed before it exists, as a choice, and reading the list mints nothing
        assert.equal(model.catalog[2].certificate, false);
        assert.equal(await redis.hget(store.TLS_KEY, store.SELF_SIGNED_FIELD), null);

        // Each listener: its default, and a dropdown whose automatic entry says what it amounts to
        assert.deepEqual(
            model.listeners.map(listener => listener.key),
            ['api', 'smtp', 'imapProxy']
        );
        const smtp = model.listeners[1];
        assert.equal(smtp.settingKey, 'smtpServerTLSCertificate');
        assert.equal(smtp.defaultId, 'acme:mail.example.com');
        assert.equal(smtp.selection, 'auto');
        assert.equal(smtp.missingLabel, null);
        assert.deepEqual(
            smtp.options.map(option => [option.id, option.selected]),
            [
                ['auto', true],
                ['manual', false],
                ['acme:mail.example.com', false],
                ['self-signed', false]
            ]
        );
        assert.equal(smtp.options[0].label, "Automatic: Let's Encrypt for mail.example.com");
        assert.equal(smtp.options[3].covers, 'generated on first use');

        // No listener answers a name with anything but the row's certificate
        assert.ok(model.certificates.every(row => row.servedBy.length === 0));
    });

    await t.test("environment material is listed as a certificate and is its listener's automatic default", async () => {
        // Material from EENGINE_SMTP_TLS_CERT used to be invisible to this model: per listener,
        // per process, described only through what the listener reported. It is read from the
        // shared environment now and listed like everything else.
        await settings.set('tlsHostnames', ['smtp.example.com']);
        const env = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });
        setEnvMaterial('smtp', env);

        const certs = fakeCerts({ 'mail.example.com': mail, 'smtp.example.com': smtp });

        const model = await status.buildCertificateStatus({ certs, served: true });

        assert.equal(model.catalog[0].id, 'env:smtp');
        assert.equal(model.catalog[0].label, 'Environment (SMTP server)');
        assert.equal(model.catalog[0].certificate.sourceLabel, 'Environment');
        assert.equal(model.catalog[0].status.text, 'From environment');
        assert.deepEqual(
            model.catalog[0].usedBy.map(entry => entry.key),
            ['smtp']
        );

        // The SMTP server presents it by default; the other listeners are not told anything by it
        assert.equal(model.listeners[1].defaultId, 'env:smtp');
        assert.equal(model.listeners[1].selection, 'auto');
        assert.equal(model.listeners[0].defaultId, 'acme:mail.example.com');
        assert.equal(model.listeners[2].defaultId, 'acme:mail.example.com');

        // The row for smtp.example.com keeps the issued certificate as what the stored sources
        // resolve to, and says the SMTP server presents its own material for the name instead -
        // once the SMTP server is on and serving TLS, which is when a client can tell
        const row = model.certificates[1];
        assert.equal(row.certificate.source, 'acme');
        assert.deepEqual(row.servedBy, [], 'nothing is switched on, so nothing presents anything');

        await settings.set('smtpServerEnabled', true);
        await settings.set('smtpServerTLSEnabled', true);
        const serving = await status.buildCertificateStatus({ certs, served: true });
        assert.deepEqual(
            serving.certificates[1].servedBy.map(entry => [entry.key, entry.label]),
            [['smtp', 'Environment (SMTP server)']]
        );
        assert.deepEqual(serving.certificates[0].servedBy, [], 'the primary name is answered the same way everywhere');
    });

    await t.test('a listener set to a certificate presents it, and the dropdown says so', async () => {
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['*.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });
        await settings.set('imapProxyServerTLSCertificate', 'manual');

        const certs = fakeCerts({ 'mail.example.com': mail });

        const model = await status.buildCertificateStatus({ certs });

        const imapProxy = model.listeners[2];
        assert.equal(imapProxy.defaultId, 'manual');
        assert.equal(imapProxy.selection, 'selected');
        assert.equal(imapProxy.options.find(option => option.id === 'manual').selected, true);
        assert.equal(imapProxy.options[0].selected, false);
        // The wildcard covers the primary name and outranks the issued certificate for it, so it
        // is also what the other two listeners decide on automatically; the chip says which is which
        assert.deepEqual(
            model.catalog.find(entry => entry.id === 'manual').usedBy.map(entry => entry.label),
            ['Admin UI and API (automatic)', 'SMTP server (automatic)', 'IMAP proxy']
        );

        // In Let's Encrypt mode the uploaded wildcard outranks the issued certificate for the
        // name, so on the row the two agree; the choice shows on the listener, not as a difference
        assert.equal(model.certificates[0].certificate.source, 'manual');
        assert.deepEqual(model.certificates[0].servedBy, []);
    });

    await t.test('a chosen certificate that no longer exists is reported, and the dropdown reads automatic', async () => {
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        await settings.set('smtpServerTLSCertificate', 'acme:gone.example.com');

        const certs = fakeCerts({ 'mail.example.com': mail });

        const model = await status.buildCertificateStatus({ certs });

        const smtp = model.listeners[1];
        assert.equal(smtp.selection, 'missing');
        assert.equal(smtp.requested, 'acme:gone.example.com');
        assert.equal(smtp.missingLabel, "Let's Encrypt for gone.example.com", 'named for the warning, not shown as a bare id');
        assert.equal(smtp.defaultId, 'acme:mail.example.com');
        // So saving the page as it stands writes the automatic choice the listener fell back to
        assert.equal(smtp.options[0].selected, true);
    });

    await t.test("a chosen default covering a name shows on that name's row", async () => {
        // The uploaded certificate is for another name and is chosen for the SMTP server. It
        // does not cover mail.example.com, so that row keeps its certificate on every listener;
        // a wildcard chosen the same way would be what the SMTP server presents for the name.
        await settings.set('tlsHostnames', ['smtp.example.com']);
        const mail = await createSelfSignedCertificate({ hostnames: ['mail.example.com'] });
        const smtp = await createSelfSignedCertificate({ hostnames: ['smtp.example.com'] });
        const manual = await createSelfSignedCertificate({ hostnames: ['smtp.example.com', 'other.example.com'] });
        await store.setManualCertificate({ cert: manual.cert, privateKey: manual.privateKey });
        await settings.set('tlsProvisioning', 'acme');
        await settings.set('smtpServerTLSCertificate', 'acme:mail.example.com');

        const certs = fakeCerts({ 'mail.example.com': mail, 'smtp.example.com': smtp });

        const model = await status.buildCertificateStatus({ certs });

        // smtp.example.com resolves to the upload (it outranks the issued one), on every listener:
        // the chosen default does not cover the name, so it changes nothing there
        assert.equal(model.certificates[1].certificate.source, 'manual');
        assert.deepEqual(model.certificates[1].servedBy, []);
        // mail.example.com is the chosen default's own name, which the row already resolves to
        assert.equal(model.certificates[0].certificate.source, 'acme');
        assert.deepEqual(model.certificates[0].servedBy, []);
    });

    await t.test('names the certificate authority it is pointed at', async () => {
        const model = await status.buildCertificateStatus({
            certs: {
                async getCertificate() {
                    return false;
                }
            }
        });

        // A staging certificate is signed by a root nobody trusts, and the old badge would have
        // called it "Valid certificate".
        assert.equal(model.acme.staging, /staging/i.test(model.acme.directoryUrl));
        assert.ok(model.acme.directoryUrl);
        assert.equal(model.mode, 'acme');
    });
});
