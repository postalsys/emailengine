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

    await t.test('counts down the last two weeks', () => {
        const label = status.certificateLabel(certificate({ validTo: new Date(Date.now() + 3 * DAY) }));

        assert.equal(label.type, 'warning');
        assert.equal(label.text, '3d left');
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

    await t.test('says a hostname has nothing rather than inventing a state for it', () => {
        assert.equal(status.certificateLabel(false).text, 'Missing');
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
        await settings.set('serviceUrl', 'https://mail.example.com');
        await settings.set('tlsHostnames', null);
        await settings.set('tlsProvisioning', null);
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
        assert.equal(model.manual.fingerprint, manual.fingerprint);
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
        assert.equal(model.certificates[0].statusVariant, 'error');
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

        assert.equal(model.certificates[0].statusVariant, 'warning');
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
