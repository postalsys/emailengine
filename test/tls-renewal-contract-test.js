'use strict';

// The contract between EmailEngine and @postalsys/certs about a renewal that did not happen.
//
// Every other provisioning test stubs the certificate handler, so on their own they prove only that
// EmailEngine reacts to a shape it made up itself. This one runs the real handler that the workers
// use, drives the real acquireCert() into its failure paths, and hands what it actually returns to
// the real provisionHostname(). If the library renames the field, stops setting it, or starts
// setting it on a path that is not a failure, this is what fails - the stubs would all still pass
// while an operator was told a broken renewal was up to date.
//
// Two things are stubbed, both because they are the parts that reach the network: the ACME order
// itself, and the renewal check that asks the CA. Everything else is the shipped code, including
// the failsafe lock the first failure arms.

const test = require('node:test');
const assert = require('node:assert').strict;

process.env.EENGINE_REDIS_PREFIX = 'test_tls_renewal_contract';
process.env.EENGINE_SECRET = 'tls-renewal-contract-test-secret';

const { createCertHandler } = require('../lib/cert-handler');
const provision = require('../lib/tls/provision');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { createSelfSignedCertificate } = require('../lib/tls/self-signed');
const registerRedisTeardown = require('./helpers/redis-teardown');

const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {}, child: () => logger };

const HOSTNAME = 'mail.example.com';

const clearKeys = async () => {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length) {
        await redis.del(keys);
    }
};

/**
 * The handler the API worker builds, with the two network-touching steps taken out: the ACME order,
 * and the renewal check that fetches the CA's advice. Domain validation stays real apart from the
 * CAA lookup, which the handler configures against Let's Encrypt and which would go to DNS.
 *
 * @param {Function} onOrder What the ACME order does
 * @returns {Object} The handler
 */
function certHandler(onOrder) {
    const certs = createCertHandler(logger);

    certs.validateDomain = async () => true;
    certs.checkRenewalDue = async () => true;
    certs.orderCert = onOrder;

    return certs;
}

/**
 * Stores a usable certificate for the hostname.
 *
 * `due` ages the stored expiry so the library's own lifetime rule calls a renewal due. Without it
 * getCertificate() short-circuits on the stored record and never reaches acquireCert() at all,
 * which is the correct behaviour and the wrong setup for a test about a failed renewal.
 *
 * @param {Object} certs Certificate handler
 * @param {Object} [opts] `{ due }`
 * @returns {Promise<Object>} The generated material
 */
async function seedCertificate(certs, opts) {
    const material = await createSelfSignedCertificate({ hostnames: [HOSTNAME] });

    await certs.setCertificateData(HOSTNAME, {
        domain: HOSTNAME,
        status: 'valid',
        cert: material.cert,
        privateKey: material.privateKey,
        ca: [],
        fingerprint: material.fingerprint,
        validFrom: material.validFrom,
        validTo: opts && opts.due ? new Date(Date.now() + 1000) : material.validTo,
        lastError: null
    });

    return material;
}

test('a failed renewal, from @postalsys/certs through to the recorded state', async t => {
    registerRedisTeardown(redis, clearKeys);

    t.beforeEach(async () => {
        await clearKeys();
        await settings.set('serviceUrl', `https://${HOSTNAME}`);
        await settings.set('tlsHostnames', null);
        await settings.set('tlsProvisioning', null);
    });

    await t.test('a failed order is recorded as a failed renewal, and every pass after it says so too', async () => {
        let orders = 0;
        const certs = certHandler(async () => {
            orders++;
            throw new Error('ACME validation failed for mail.example.com');
        });
        const material = await seedCertificate(certs, { due: true });

        const result = await provision.provisionHostname({ certs, logger, hostname: HOSTNAME });

        assert.equal(result.success, false);
        assert.match(result.message, /ACME validation failed/);
        assert.equal((await provision.getProvisioningStatus())[HOSTNAME].state, 'renewalFailed');

        // The listener has to keep serving something, which is why the library hands the old
        // certificate back rather than throwing
        const stored = await certs.getCertificate(HOSTNAME, true);
        assert.equal(stored.status, 'valid');
        assert.equal(stored.cert, material.cert);

        // That failure armed the library's failsafe lock, so the next pass does not even try. It is
        // still a renewal that was asked for and did not happen, and the operator has to keep being
        // told - a single report an hour before the certificate expires is not a warning.
        const blocked = await provision.provisionHostname({ certs, logger, hostname: HOSTNAME });

        assert.equal(orders, 1, 'the second pass did not order anything, which is the branch under test');
        assert.equal(blocked.success, false);
        assert.equal((await provision.getProvisioningStatus())[HOSTNAME].state, 'renewalFailed');
    });

    await t.test('a stored failure that this pass did not repeat is not reported', async () => {
        // The record keeps `lastError` until a successful order clears it. A pass that renewed
        // nothing and failed at nothing must not read that as its own result - which is exactly
        // what EmailEngine used to do, and why the library grew a separate field for it.
        const certs = certHandler(async () => {
            throw new Error('this order is never reached');
        });
        await seedCertificate(certs);
        await certs.setCertificateData(HOSTNAME, { lastError: { err: 'an order that failed weeks ago', time: new Date(Date.now() - 30 * 24 * 3600 * 1000) } });

        const result = await provision.provisionHostname({ certs, logger, hostname: HOSTNAME });

        assert.equal(result.success, true);
        assert.equal((await provision.getProvisioningStatus())[HOSTNAME].state, 'valid');
    });
});
