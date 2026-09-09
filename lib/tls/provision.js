'use strict';

// Getting a certificate, and knowing why you did not get one.
//
// Provisioning used to happen on the click of the "Enable TLS" checkbox: a foreground HTTP request
// held open for the length of an ACME order, behind a modal spinner, before the setting it belonged
// to had been saved. It failed the way that arrangement has to fail. A reverse proxy with a thirty
// second timeout killed the request while the order carried on; a failure silently unchecked the
// box, so the page stopped matching the stored setting; and the reason never reached the operator,
// because acquireCert() answers a failed order by returning the previous record, which for a first
// certificate is nothing at all.
//
// So provisioning is a background task with a recorded state, and the UI watches that state. The
// reconciler below is the only thing that orders certificates; the button in the admin UI asks it
// to run now rather than doing the work itself.

const crypto = require('crypto');
const { fetch: fetchCmd } = require('undici');

const { redis } = require('../db');
const settings = require('../settings');
const { REDIS_PREFIX, BLOCK_TLS_RENEW, TLS_RETRY_AFTER_FAILURE, TLS_PREFLIGHT_TTL, TLS_PREFLIGHT_TIMEOUT } = require('../consts');
const { emitChangeEvent, reloadTlsCertificates, httpAgent } = require('../tools');
const { validateWebhookTarget } = require('../webhook-egress');
const { getCertificateHostnames, acmeEligibleHostnames, getAcmeCertificate } = require('./store');

const STATUS_KEY = `${REDIS_PREFIX}tls:status`;
const PROBE_KEY = `${REDIS_PREFIX}tls:probe`;

// Orders this worker has in flight. Not a lock - the certificate library holds a Redis lock per
// domain, so two workers ordering at once is already handled. This only stops one worker from
// stacking background tasks for the same name while an order is running.
const inFlight = new Set();

/**
 * Reads the recorded provisioning state for every hostname.
 *
 * @returns {Promise<Object>} Hostname to `{ state, message, attempted, ... }`
 */
async function getProvisioningStatus() {
    const entries = await redis.hgetall(STATUS_KEY);
    const status = {};

    for (const hostname of Object.keys(entries || {})) {
        try {
            status[hostname] = JSON.parse(entries[hostname]);
        } catch (err) {
            // a record that does not parse is a record that says nothing
        }
    }

    return status;
}

/**
 * Records provisioning state and tells any open admin page about it. The event is what replaces the
 * blocking modal: the page that asked for a certificate sees the order start, succeed or fail
 * without holding a request open for it.
 *
 * @param {Object} logger Worker logger
 * @param {string} hostname Name being provisioned
 * @param {Object} status State to record
 * @returns {Promise<Object>} The recorded state
 */
async function setProvisioningStatus(logger, hostname, status) {
    const record = Object.assign({ hostname, updated: new Date().toISOString() }, status);

    try {
        await redis.hset(STATUS_KEY, hostname, JSON.stringify(record));
    } catch (err) {
        logger.error({ msg: 'Failed to store certificate provisioning state', hostname, err });
    }

    await emitChangeEvent(logger, null, 'tlsCertificateState', record.state, record);

    return record;
}

async function clearProvisioningStatus(hostname) {
    return await redis.hdel(STATUS_KEY, hostname);
}

/**
 * Arms a token the ACME challenge route will answer, so the preflight can prove that a request from
 * the public internet reaches this instance's challenge path.
 *
 * @returns {Promise<Object>} `{ token, value }`
 */
async function armPreflightProbe() {
    const token = `ee-preflight-${crypto.randomBytes(16).toString('hex')}`;
    const value = crypto.randomBytes(32).toString('base64url');

    // One command, so the key cannot outlive its expiry by having the second leg fail.
    await redis.set(`${PROBE_KEY}:${token}`, value, 'EX', TLS_PREFLIGHT_TTL);

    return { token, value };
}

/**
 * The answer for a probe token, if one is armed. Called by the ACME challenge route before it hands
 * the token to the certificate library.
 *
 * @param {string} token Token from the request path
 * @returns {Promise<string|false>} The expected response body
 */
async function resolvePreflightProbe(token) {
    if (!token || !/^ee-preflight-[0-9a-f]{32}$/.test(token)) {
        return false;
    }

    return (await redis.get(`${PROBE_KEY}:${token}`)) || false;
}

/**
 * Checks whether a Let's Encrypt http-01 challenge for this hostname could succeed, by making the
 * request the CA will make.
 *
 * This is the check that pays for itself. Automatic certificates need the name to resolve and port
 * 80 to reach EmailEngine's challenge path, neither of which is visible from the admin UI, and both
 * of which fail as an opaque ACME error minutes later. Here they fail immediately, by name.
 *
 * The request goes to a hostname the operator configured as their own service URL, and only its
 * status code and whether the body matched a token EmailEngine just generated are reported back.
 *
 * @param {Object} opts
 * @param {string} opts.hostname Name to check
 * @param {Object} opts.logger Worker logger
 * @returns {Promise<Object>} `{ success, hostname, message, url, status }`
 */
async function runPreflight(opts) {
    const { hostname, logger } = opts;

    const probe = await armPreflightProbe();
    const url = `http://${hostname}/.well-known/acme-challenge/${probe.token}`;

    // The same egress policy webhooks and autodiscovery are held to. The hostname is configuration
    // rather than caller input, but it is still a name the server is asked to fetch, and a name
    // that resolves into a blocked range is one Let's Encrypt could never reach either - so
    // refusing it is both the safe answer and the true one.
    if (validateWebhookTarget) {
        try {
            await validateWebhookTarget(url);
        } catch (err) {
            return {
                success: false,
                hostname,
                url,
                message: `${hostname} resolves to an address this instance will not connect to (${err.message}). Let's Encrypt could not reach it either.`
            };
        }
    }

    let res;
    try {
        res = await fetchCmd(url, {
            method: 'GET',
            redirect: 'follow',
            // The webhook dispatcher re-applies the policy as its connect-time lookup, so the
            // address vetted above is the address connected to, on the first hop and on any
            // redirect the CA would also follow.
            dispatcher: httpAgent.webhook,
            signal: AbortSignal.timeout(TLS_PREFLIGHT_TIMEOUT),
            headers: { 'User-Agent': 'EmailEngine ACME preflight' }
        });
    } catch (err) {
        logger.info({ msg: 'Certificate preflight could not reach the challenge path', hostname, url, err });

        return {
            success: false,
            hostname,
            url,
            message: `Could not reach http://${hostname}/ from this server (${err.cause ? err.cause.message || err.message : err.message}). The name has to resolve to this machine and port 80 has to reach EmailEngine.`
        };
    }

    if (!res.ok) {
        return {
            success: false,
            hostname,
            url,
            status: res.status,
            message: `http://${hostname}/.well-known/acme-challenge/ answered ${res.status}. Something other than EmailEngine is serving that path.`
        };
    }

    const body = (await res.text()).trim();

    if (body !== probe.value) {
        return {
            success: false,
            hostname,
            url,
            status: res.status,
            message: `http://${hostname}/ is reachable but answered with content from a different server. Point port 80 for this name at EmailEngine, or forward /.well-known/acme-challenge/ to it.`
        };
    }

    return {
        success: true,
        hostname,
        url,
        status: res.status,
        message: `Let's Encrypt can reach this instance at http://${hostname}/`
    };
}

/**
 * Orders (or renews) the certificate for one hostname and records what happened.
 *
 * @param {Object} opts
 * @param {Object} opts.certs @postalsys/certs handler
 * @param {Object} opts.logger Worker logger
 * @param {string} opts.hostname Name to provision
 * @returns {Promise<Object>} `{ success, changed, hostname, message }`
 */
async function provisionHostname(opts) {
    const { certs, logger, hostname } = opts;

    const before = await getAcmeCertificate(certs, hostname);

    await setProvisioningStatus(logger, hostname, { state: 'ordering', message: `Requesting a certificate for ${hostname}` });

    let record;
    let failure;

    try {
        record = await certs.getCertificate(hostname, false);
    } catch (err) {
        failure = err.message;
        logger.error({ msg: 'Failed to provision a TLS certificate', hostname, err });
    }

    if (record && record.status === 'valid' && record.cert) {
        const changed = !before || before.fingerprint !== record.fingerprint;

        // A renewal that failed while a usable certificate was already stored comes back as that
        // certificate, still `valid` so the listener keeps serving it, with the reason attached.
        // Reading only the status reported "the certificate is up to date" to an operator whose
        // challenge routing or CA access had broken, and kept saying it on every pass while the
        // certificate walked towards its expiry date.
        //
        // `renewalError` and not `lastError`: the first describes this call, the second describes
        // the record and outlives the failure it names, because acquireCert() answers from the
        // stored record whenever renewal is not due or another worker is already on it.
        const renewError = record.renewalError;
        if (renewError && renewError.err) {
            await setProvisioningStatus(logger, hostname, {
                state: 'renewalFailed',
                attempted: Date.now(),
                // The failure's own time, so a page rendered days later does not read as if the
                // renewal had just been attempted
                failedAt: renewError.time || null,
                fingerprint: record.fingerprint,
                validTo: record.validTo,
                message: `Could not renew the certificate for ${hostname}, still serving the current one: ${renewError.err}`
            });

            // The material is usable, so `changed` still drives the listener reload - only the
            // reporting says the renewal did not happen
            return { success: false, changed, hostname, message: renewError.err };
        }

        await setProvisioningStatus(logger, hostname, {
            state: 'valid',
            attempted: Date.now(),
            fingerprint: record.fingerprint,
            validTo: record.validTo,
            message: changed ? `Installed a certificate for ${hostname}` : `The certificate for ${hostname} is up to date`
        });

        return { success: true, changed, hostname };
    }

    // acquireCert() answers a blocked or unvalidatable domain by returning what was already
    // stored, which for a first certificate is nothing. The reason it did not say is in the
    // record it wrote, so read it back rather than reporting "failed" and nothing else.
    if (!failure) {
        let stored;
        try {
            stored = await certs.getCertificate(hostname, true);
        } catch (err) {
            stored = false;
        }

        failure =
            (stored && stored.lastError && stored.lastError.err) ||
            `Could not get a certificate for ${hostname}. Check that the name resolves to this server and that port 80 is reachable.`;
    }

    await setProvisioningStatus(logger, hostname, { state: 'failed', attempted: Date.now(), message: failure });

    return { success: false, changed: false, hostname, message: failure };
}

/**
 * Decides whether a hostname needs an order right now.
 *
 * @param {Object} opts
 * @param {Object} opts.certs @postalsys/certs handler
 * @param {string} opts.hostname Name to consider
 * @param {Object} opts.status Recorded provisioning state for that name
 * @returns {Promise<boolean>} True when an order should be attempted
 */
async function needsProvisioning(opts) {
    const { certs, hostname, status } = opts;

    const attempted = (status && status.attempted) || 0;

    let record;
    try {
        record = await certs.getCertificate(hostname, true);
    } catch (err) {
        record = false;
    }

    // No certificate at all. The renewal timer used to require an existing record before it would
    // do anything, so a name that had never been provisioned - or whose record was lost with a
    // flushed Redis or a restored backup - was never provisioned by the timer either, and the
    // listener stayed down until somebody clicked the checkbox twice.
    if (!record || !record.cert || record.status !== 'valid') {
        return Date.now() - attempted > TLS_RETRY_AFTER_FAILURE;
    }

    if (record.lastCheck && record.lastCheck > new Date(Date.now() - BLOCK_TLS_RENEW)) {
        return false;
    }

    // Asks Let's Encrypt whether the certificate should be replaced yet, through ACME Renewal
    // Information, falling back to a threshold scaled to the lifetime the CA issued. Asking matters
    // because a mass revocation is the one case where the CA needs a certificate replaced long
    // before its own schedule would.
    try {
        return await certs.checkRenewalDue(hostname, record);
    } catch (err) {
        return false;
    }
}

/**
 * Asks for certificates now, from the admin UI's button.
 *
 * The whole vocabulary of provisioning states lives here rather than half of it in a route: a
 * request that the reconciler declines - because automatic certificates are switched off, or
 * because a CA cannot validate the name - has to record why, or the badge reads "Requesting"
 * forever with nothing on the way to replace it.
 *
 * Returns as soon as the work is scheduled. An ACME order takes seconds at best and minutes when
 * the CA is retrying, and the request that asks for one used to be held open for all of it.
 *
 * @param {Object} opts
 * @param {Object} opts.certs @postalsys/certs handler
 * @param {Object} opts.logger Worker logger
 * @param {Function} opts.call Worker call function, for the listener reload
 * @param {string[]} opts.hostnames Names to provision
 * @returns {Promise<Object>} `{ accepted, declined }`
 */
async function requestProvisioning(opts) {
    const { certs, logger, call, hostnames } = opts;

    const mode = (await settings.get('tlsProvisioning')) || 'acme';
    const eligible = acmeEligibleHostnames(hostnames);

    const accepted = [];
    const declined = [];

    for (const hostname of hostnames) {
        let reason = null;

        if (mode !== 'acme') {
            reason = 'Automatic certificates are switched off for this instance';
        } else if (!eligible.includes(hostname)) {
            reason = `Let's Encrypt can not validate ${hostname}. Automatic certificates need a public domain name.`;
        } else if (inFlight.has(hostname)) {
            // Already ordering. Saying so beats silently starting a second order, and beats
            // overwriting the state the running order is reporting through.
            accepted.push(hostname);
            continue;
        }

        if (reason) {
            declined.push({ hostname, reason });
            await setProvisioningStatus(logger, hostname, { state: 'skipped', attempted: Date.now(), message: reason });
            continue;
        }

        accepted.push(hostname);
        inFlight.add(hostname);
        await setProvisioningStatus(logger, hostname, { state: 'queued', message: 'Waiting to request a certificate' });
    }

    const ordering = accepted.filter(hostname => inFlight.has(hostname));

    if (ordering.length) {
        reconcileCertificates({ certs, logger, call, hostnames: ordering, force: true })
            .catch(err => logger.error({ msg: 'Certificate provisioning failed', err }))
            .finally(() => {
                for (const hostname of ordering) {
                    inFlight.delete(hostname);
                }
            });
    }

    return { accepted, declined };
}

/**
 * One pass of the reconciler: brings every configured hostname to a valid certificate, and reloads
 * the listeners when anything changed.
 *
 * @param {Object} opts
 * @param {Object} opts.certs @postalsys/certs handler
 * @param {Object} opts.logger Worker logger
 * @param {Function} opts.call Worker call function, for the listener reload
 * @param {string[]} [opts.hostnames] Names to reconcile; defaults to the configured ones
 * @param {boolean} [opts.force] Order even when the recorded state says to wait
 * @returns {Promise<Object>} `{ results, changed }`
 */
async function reconcileCertificates(opts) {
    const { certs, logger, call, force } = opts;

    const mode = (await settings.get('tlsProvisioning')) || 'acme';

    const configured = await getCertificateHostnames();
    const targets = opts.hostnames || configured;
    const hostnames = acmeEligibleHostnames(targets);

    // Derived rather than hooked on the settings form: tlsHostnames, tlsProvisioning and serviceUrl
    // are all writable through the REST API too, and a state record for a name nobody serves any
    // more reads as a broken instance.
    if (!opts.hostnames) {
        const status = await getProvisioningStatus();
        for (const hostname of Object.keys(status)) {
            if (!configured.includes(hostname)) {
                await clearProvisioningStatus(hostname);
            }
        }
    }

    if (mode !== 'acme' || !hostnames.length) {
        return { results: [], changed: false, skipped: mode !== 'acme' ? mode : 'no-eligible-hostname' };
    }

    const status = await getProvisioningStatus();
    const results = [];
    let changed = false;

    for (const hostname of hostnames) {
        if (!force && !(await needsProvisioning({ certs, hostname, status: status[hostname] }))) {
            continue;
        }

        const result = await provisionHostname({ certs, logger, hostname });
        results.push(result);
        changed = changed || result.changed;

        // The library records its own last-check time on the renewal path; do it here too so a
        // renewal that was skipped or failed does not have the check repeated on the next pass.
        try {
            await certs.setCertificateData(hostname, { lastCheck: new Date() });
        } catch (err) {
            logger.error({ msg: 'Failed to record the certificate check time', hostname, err });
        }
    }

    if (changed) {
        await reloadTlsCertificates(call, logger, { hostnames });
    }

    return { results, changed };
}

module.exports = {
    STATUS_KEY,
    requestProvisioning,
    getProvisioningStatus,
    setProvisioningStatus,
    clearProvisioningStatus,
    armPreflightProbe,
    resolvePreflightProbe,
    runPreflight,
    provisionHostname,
    needsProvisioning,
    reconcileCertificates
};
