'use strict';

// The provisioning reconciler (lib/tls/provision.js).
//
// Three behaviors here were bugs before this module existed:
//
//   - a hostname with no certificate at all was never provisioned automatically. The renewal timer
//     read the record first and did nothing when there was none, so a fresh install, a flushed
//     Redis or a restored backup left the listeners down until an admin clicked a checkbox twice.
//   - a failed order reported nothing. acquireCert() answers a blocked or unvalidatable domain by
//     returning the previous record, which for a first certificate is `false`, and the UI turned
//     that into "Failed to provision a certificate" with no reason attached.
//   - ordering was done in the foreground of an HTTP request that a reverse proxy would time out.
//
// The certificate handler is a stub: what is under test is when EmailEngine decides to order, and
// what it records about the outcome.

const test = require('node:test');
const assert = require('node:assert').strict;

process.env.EENGINE_REDIS_PREFIX = 'test_tls_provision';
process.env.EENGINE_SECRET = 'tls-provision-test-secret';

const provision = require('../lib/tls/provision');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX, TLS_RETRY_AFTER_FAILURE, BLOCK_TLS_RENEW } = require('../lib/consts');
const { createSelfSignedCertificate } = require('../lib/tls/self-signed');

const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {} };

/**
 * A stub certificate handler that records what it was asked for.
 *
 * @param {Object} opts `{ records, onAcquire }`
 * @returns {Object} Handler plus the call log
 */
function stubCerts(opts) {
    const options = opts || {};
    const records = options.records || {};
    const calls = [];

    return {
        calls,
        async getCertificate(hostname, skipAcquire) {
            calls.push({ hostname, skipAcquire });
            if (!skipAcquire && options.onAcquire) {
                const result = await options.onAcquire(hostname);
                if (result) {
                    records[hostname] = result;
                }
                return records[hostname] || false;
            }
            return records[hostname] || false;
        },
        async checkRenewalDue(hostname) {
            calls.push({ hostname, renewalCheck: true });
            return !!options.renewalDue;
        },
        async setCertificateData(hostname, updates) {
            records[hostname] = Object.assign({}, records[hostname], updates);
        }
    };
}

async function issued(hostname) {
    const material = await createSelfSignedCertificate({ hostnames: [hostname] });
    return {
        status: 'valid',
        cert: material.cert,
        privateKey: material.privateKey,
        fingerprint: material.fingerprint,
        validTo: material.validTo
    };
}

test('certificate provisioning', async t => {
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

    await t.test('a hostname with no certificate is provisioned', async () => {
        // The regression that left listeners down after a flushed Redis: the old timer required an
        // existing record before it would do anything.
        const certs = stubCerts({});
        assert.equal(await provision.needsProvisioning({ certs, hostname: 'mail.example.com', status: null }), true);
    });

    await t.test('a hostname whose last attempt just failed is left alone for a while', async () => {
        const certs = stubCerts({});

        assert.equal(
            await provision.needsProvisioning({ certs, hostname: 'mail.example.com', status: { state: 'failed', attempted: Date.now() } }),
            false,
            'not retried immediately'
        );

        assert.equal(
            await provision.needsProvisioning({
                certs,
                hostname: 'mail.example.com',
                status: { state: 'failed', attempted: Date.now() - TLS_RETRY_AFTER_FAILURE - 1000 }
            }),
            true,
            'but a fixed problem recovers on its own'
        );
    });

    await t.test('a valid certificate checked recently is not looked at again', async () => {
        const certs = stubCerts({ records: { 'mail.example.com': Object.assign(await issued('mail.example.com'), { lastCheck: new Date() }) } });

        assert.equal(await provision.needsProvisioning({ certs, hostname: 'mail.example.com', status: null }), false);
        assert.equal(certs.calls.filter(call => call.renewalCheck).length, 0, 'the CA is not asked');
    });

    await t.test('a valid certificate that is due for renewal is renewed', async () => {
        const record = Object.assign(await issued('mail.example.com'), { lastCheck: new Date(Date.now() - BLOCK_TLS_RENEW - 1000) });

        const notDue = stubCerts({ records: { 'mail.example.com': record } });
        assert.equal(await provision.needsProvisioning({ certs: notDue, hostname: 'mail.example.com', status: null }), false);

        const due = stubCerts({ records: { 'mail.example.com': record }, renewalDue: true });
        assert.equal(await provision.needsProvisioning({ certs: due, hostname: 'mail.example.com', status: null }), true);

        // Asking the CA is what catches a mass revocation, where a certificate has to be replaced
        // long before its own schedule would say so.
        assert.ok(due.calls.some(call => call.renewalCheck));
    });

    await t.test('a successful order is recorded and reported as changed', async () => {
        const certs = stubCerts({ onAcquire: hostname => issued(hostname) });

        const result = await provision.provisionHostname({ certs, logger, hostname: 'mail.example.com' });

        assert.equal(result.success, true);
        assert.equal(result.changed, true);

        const status = await provision.getProvisioningStatus();
        assert.equal(status['mail.example.com'].state, 'valid');
        assert.ok(status['mail.example.com'].fingerprint);
    });

    await t.test('a repeated order that returns the same certificate is not reported as changed', async () => {
        const record = await issued('mail.example.com');
        const certs = stubCerts({ records: { 'mail.example.com': record }, onAcquire: () => record });

        const result = await provision.provisionHostname({ certs, logger, hostname: 'mail.example.com' });

        // What stops repeated clicks from restarting both listeners for nothing.
        assert.equal(result.success, true);
        assert.equal(result.changed, false);
    });

    await t.test('a thrown failure keeps its message', async () => {
        const certs = stubCerts({
            onAcquire() {
                throw new Error('urn:ietf:params:acme:error:unauthorized');
            }
        });

        const result = await provision.provisionHostname({ certs, logger, hostname: 'mail.example.com' });

        assert.equal(result.success, false);
        assert.match(result.message, /acme:error:unauthorized/);
        assert.equal((await provision.getProvisioningStatus())['mail.example.com'].state, 'failed');
    });

    await t.test('a silent failure is explained from the record the library wrote', async () => {
        // acquireCert() returns the previous record when the domain cannot be validated or the
        // failsafe lock is armed. For a first certificate that is `false`, and the reason it did
        // not say is in lastError.
        const certs = {
            async getCertificate(hostname, skipAcquire) {
                if (skipAcquire) {
                    return { status: 'failed', lastError: { err: 'mail.example.com is not a valid domain name' } };
                }
                return false;
            },
            async setCertificateData() {}
        };

        const result = await provision.provisionHostname({ certs, logger, hostname: 'mail.example.com' });

        assert.equal(result.success, false);
        assert.match(result.message, /not a valid domain name/);
    });

    await t.test('a silent failure with nothing recorded still says what to check', async () => {
        const certs = {
            async getCertificate() {
                return false;
            },
            async setCertificateData() {}
        };

        const result = await provision.provisionHostname({ certs, logger, hostname: 'mail.example.com' });

        assert.equal(result.success, false);
        assert.match(result.message, /port 80/);
    });

    await t.test('the reconciler orders for every eligible hostname and reloads the listeners once', async () => {
        await settings.set('tlsHostnames', ['smtp.example.com', '192.0.2.10', 'mail.local']);

        const certs = stubCerts({ onAcquire: hostname => issued(hostname) });
        const commands = [];

        const result = await provision.reconcileCertificates({
            certs,
            logger,
            call: async message => commands.push(message.cmd)
        });

        assert.deepEqual(
            result.results.map(entry => entry.hostname),
            ['mail.example.com', 'smtp.example.com'],
            'an address literal and a private-use suffix are skipped, not attempted'
        );

        // Every listener, once, and without restarting any of them.
        assert.deepEqual(commands, ['apiReloadCertificates', 'smtpReloadCertificates', 'imapProxyReloadCertificates']);
    });

    await t.test('the reconciler does nothing when automatic certificates are switched off', async () => {
        await settings.set('tlsProvisioning', 'self-signed');

        const certs = stubCerts({ onAcquire: hostname => issued(hostname) });
        const result = await provision.reconcileCertificates({ certs, logger, call: async () => {} });

        assert.equal(result.skipped, 'self-signed');
        assert.deepEqual(result.results, []);
    });

    await t.test('the reconciler does nothing when no hostname can be validated', async () => {
        await settings.set('serviceUrl', 'https://127.0.0.1:3000');

        const certs = stubCerts({ onAcquire: hostname => issued(hostname) });
        const result = await provision.reconcileCertificates({ certs, logger, call: async () => {} });

        assert.equal(result.skipped, 'no-eligible-hostname');
    });

    await t.test('the reconciler does not reload the listeners when nothing changed', async () => {
        const record = await issued('mail.example.com');
        const certs = stubCerts({ records: { 'mail.example.com': record }, onAcquire: () => record });
        const commands = [];

        await provision.reconcileCertificates({ certs, logger, call: async message => commands.push(message.cmd), force: true });

        assert.deepEqual(commands, []);
    });

    await t.test('a preflight probe is answered once and only for its own token', async () => {
        const probe = await provision.armPreflightProbe();

        assert.match(probe.token, /^ee-preflight-[0-9a-f]{32}$/);
        assert.equal(await provision.resolvePreflightProbe(probe.token), probe.value);

        // A real ACME challenge token must never be mistaken for a probe, and the reverse.
        assert.equal(await provision.resolvePreflightProbe('some-acme-token'), false);
        assert.equal(await provision.resolvePreflightProbe(''), false);
        assert.equal(await provision.resolvePreflightProbe('ee-preflight-nothexatall'), false);
    });

    await t.test('a declined request records why, rather than leaving it queued forever', async () => {
        // The reconciler answers a mode of "self-signed" by doing nothing. A request that only
        // wrote "queued" and handed off to it left the badge reading "Requesting" with nothing on
        // the way to replace it.
        await settings.set('tlsProvisioning', 'self-signed');

        const result = await provision.requestProvisioning({
            certs: stubCerts({}),
            logger,
            call: async () => {},
            hostnames: ['mail.example.com']
        });

        assert.deepEqual(result.accepted, []);
        assert.equal(result.declined.length, 1);

        const status = (await provision.getProvisioningStatus())['mail.example.com'];
        assert.equal(status.state, 'skipped');
        assert.match(status.message, /switched off/);
    });

    await t.test('a name no certificate authority can validate is declined by name', async () => {
        await settings.set('serviceUrl', 'https://mail.local');

        const result = await provision.requestProvisioning({
            certs: stubCerts({}),
            logger,
            call: async () => {},
            hostnames: ['mail.local']
        });

        assert.deepEqual(result.accepted, []);
        assert.match((await provision.getProvisioningStatus())['mail.local'].message, /public domain name/);
    });

    await t.test('an accepted request is queued and reported without waiting for the order', async () => {
        const certs = stubCerts({ onAcquire: hostname => issued(hostname) });

        const result = await provision.requestProvisioning({
            certs,
            logger,
            call: async () => {},
            hostnames: ['mail.example.com']
        });

        assert.deepEqual(result.accepted, ['mail.example.com']);
        assert.deepEqual(result.declined, []);

        // The state is written before the order starts, so the page has something to follow.
        assert.ok(['queued', 'ordering', 'valid'].includes((await provision.getProvisioningStatus())['mail.example.com'].state));
    });

    await t.test('provisioning state can be cleared for a hostname that is no longer served', async () => {
        await provision.setProvisioningStatus(logger, 'gone.example.com', { state: 'failed', message: 'nope' });
        assert.ok((await provision.getProvisioningStatus())['gone.example.com']);

        await provision.clearProvisioningStatus('gone.example.com');
        assert.equal((await provision.getProvisioningStatus())['gone.example.com'], undefined);
    });
});
