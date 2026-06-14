'use strict';

// License-validation feature beacon.
//
// Collects a compact, anonymized snapshot of which features are enabled and exercised on this
// instance, to be piggybacked onto the existing daily license-validation POST. The intent is to
// learn whether deprecation-candidate features are still in use in the field.
//
// Privacy: the snapshot contains only enable-flags, provider type names, coarse magnitude tiers
// (NOT raw counts), exercised-usage booleans, and runtime context. It never includes account
// addresses, URLs, credentials, or any other PII/secrets.
//
// Reliability: collection is strictly best-effort. Every field is isolated so one failing Redis
// read degrades that field rather than the whole snapshot, and collectBeacon never throws - on a
// catastrophic failure it returns null and the license call proceeds with its original fields.
// The caller is expected to also time-box this with withTimeout().

const crypto = require('crypto');
const msgpack = require('msgpack5')();

const settings = require('./settings');
const { getCounterValues, hasEnvValue, readEnvValue, getBoolean } = require('./tools');
const { REDIS_PREFIX, EE_DOCKER_LEGACY } = require('./consts');
const { oauth2Apps } = require('./oauth2-apps');
const passkeys = require('./passkeys');
const featureFlags = require('./feature-flags');
const { documentStoreFeatureEnabled } = require('./document-store');

// Beacon schema version. Bump when the meaning of codes changes so the license server can adapt.
const SCHEMA_VERSION = 1;

// Window for "exercised recently" usage signals. A week smooths over quiet days so the digest
// (and therefore the full-payload sends) does not churn day to day.
const USE_WINDOW_SECONDS = 7 * 24 * 3600;

// Skip the per-route webhook content scan above this many routes (keeps the collector cheap).
const WH_SCAN_LIMIT = 250;

// Time-box for a single collection so a slow Redis can never delay license validation.
const COLLECT_TIMEOUT_MS = 2000;

// Resend the full snapshot at least this often even when its digest has not changed.
const FULL_RESEND_INTERVAL_MS = 30 * 24 * 3600 * 1000;

// Map a raw count to a coarse magnitude tier (powers of ten). Values are buckets, never counts.
function tier(n) {
    n = Number(n) || 0;
    if (n <= 0) return 0;
    if (n === 1) return 1;
    if (n < 10) return 2;
    if (n < 100) return 3;
    if (n < 1000) return 4;
    if (n < 10000) return 5;
    return 6;
}

// Truthiness for boolean-ish settings (schema booleans arrive as real booleans; legacy/raw values
// may be strings or arrays).
function truthy(value) {
    if (value === true) {
        return true;
    }
    if (typeof value === 'number') {
        return value !== 0;
    }
    if (Array.isArray(value)) {
        return value.length > 0;
    }
    if (typeof value === 'string') {
        return /^(y|yes|true|t|1)$/i.test(value.trim());
    }
    return false;
}

// Non-empty check for string-valued settings (URLs, keys, scripts) without inspecting the value.
function nonEmpty(value) {
    if (typeof value === 'string') {
        return value.trim().length > 0;
    }
    return truthy(value);
}

// Deterministic serialization: object keys sorted recursively. Arrays are pre-sorted at build time.
// Produces a stable string so the digest only changes when the snapshot meaningfully changes.
function stableStringify(value) {
    if (Array.isArray(value)) {
        return '[' + value.map(stableStringify).join(',') + ']';
    }
    if (value && typeof value === 'object') {
        return (
            '{' +
            Object.keys(value)
                .sort()
                .map(key => JSON.stringify(key) + ':' + stableStringify(value[key]))
                .join(',') +
            '}'
        );
    }
    return JSON.stringify(value);
}

// Resolve the install channel, mirroring lib/ui-routes/dashboard-routes.js.
function installChannel() {
    if (getBoolean(readEnvValue('EENGINE_DOCEAN'))) {
        return 'docean';
    }
    if (typeof readEnvValue('RENDER_SERVICE_SLUG') === 'string' && readEnvValue('RENDER_SERVICE_SLUG')) {
        return 'render';
    }
    if (getBoolean(readEnvValue('EENGINE_INSTALL_SCRIPT'))) {
        return 'script';
    }
    if (EE_DOCKER_LEGACY) {
        return 'docker-legacy';
    }
    return 'general';
}

// Race a promise against a timeout so a slow Redis can never delay license validation.
function withTimeout(promise, ms) {
    return Promise.race([
        promise,
        new Promise((resolve, reject) => {
            setTimeout(() => reject(new Error('Beacon collection timed out')), ms).unref();
        })
    ]);
}

// Build the diagnostic snapshot and its digest. Returns { fh, diag } or null on failure.
async function collectBeacon({ redis, logger }) {
    // Isolate a single field: log and swallow so one failure does not abort the whole snapshot.
    const safe = async fn => {
        try {
            return await fn();
        } catch (err) {
            if (logger) {
                logger.error({ msg: 'Beacon field collection failed', err });
            }
            return undefined;
        }
    };

    try {
        const diag = { v: SCHEMA_VERSION };

        const s =
            (await safe(() =>
                settings.getMulti(
                    'smtpServerEnabled',
                    'imapProxyServerEnabled',
                    'enableApiProxy',
                    'trackOpens',
                    'trackClicks',
                    'webhooksEnabled',
                    'openAiAPIKey',
                    'generateEmailSummary',
                    'openAiGenerateEmbeddings',
                    'openAiAPIUrl',
                    'openAiPreProcessingFn',
                    'proxyEnabled',
                    'httpProxyEnabled',
                    'localAddresses',
                    'sentryEnabled',
                    'authServer',
                    'imapIndexer',
                    'totpEnabled',
                    'documentStoreEnabled',
                    'documentStoreGenerateEmbeddings',
                    'documentStorePreProcessingEnabled',
                    'gmailEnabled',
                    'outlookEnabled',
                    'mailRuEnabled',
                    'trackSentMessages'
                )
            )) || {};

        const on = key => truthy(s[key]);

        // Enabled-feature codes (presence = on; codes are omitted when off).
        const feat = [];
        if (on('smtpServerEnabled')) feat.push('smtp');
        if (on('imapProxyServerEnabled')) feat.push('imapproxy');
        if (on('enableApiProxy')) feat.push('apiproxy');
        if (on('trackOpens')) feat.push('track_o');
        if (on('trackClicks')) feat.push('track_c');
        if (on('webhooksEnabled')) feat.push('webhooks');
        if (nonEmpty(s.openAiAPIKey)) feat.push('ai');
        if (on('generateEmailSummary')) feat.push('ai_sum');
        if (on('openAiGenerateEmbeddings')) feat.push('ai_embed');
        if (nonEmpty(s.openAiAPIUrl)) feat.push('ai_url');
        if (nonEmpty(s.openAiPreProcessingFn)) feat.push('ai_prefn');
        if (on('proxyEnabled')) feat.push('proxy');
        if (on('httpProxyEnabled')) feat.push('httpproxy');
        if (truthy(s.localAddresses)) feat.push('localaddr');
        if (on('sentryEnabled')) feat.push('sentry');
        if (nonEmpty(s.authServer)) feat.push('authsrv');
        if (s.imapIndexer === 'fast') feat.push('idx_fast');
        if (on('totpEnabled')) feat.push('totp');
        if (hasEnvValue('OKTA_OAUTH2_ISSUER') && hasEnvValue('OKTA_OAUTH2_CLIENT_ID') && hasEnvValue('OKTA_OAUTH2_CLIENT_SECRET')) {
            feat.push('okta');
        }
        if (await safe(() => passkeys.hasPasskeys())) {
            feat.push('passkey');
        }
        diag.feat = feat.sort();

        // Entity magnitude tiers (buckets, not counts).
        const scard = key => safe(() => redis.scard(`${REDIS_PREFIX}${key}`));
        const rawAccounts = Number(await scard('ia:accounts')) || 0;
        diag.tiers = {
            acct: tier(rawAccounts),
            oapp: tier(await scard('oapp:i')),
            gw: tier(await scard('gateways')),
            wh: tier(await scard('wh:i')),
            tpl: tier(await scard('tpl::i')),
            bl: tier(await safe(() => redis.hlen(`${REDIS_PREFIX}lists:unsub:lists`)))
        };

        // Provider mix. `oapp` = provider types of configured OAuth apps; `prov` = provider types
        // that actually have accounts (plus `imap` for any non-OAuth accounts). Only the app id and
        // provider type are read from the sanitized app listing - no secrets are inspected.
        await safe(async () => {
            const res = await oauth2Apps.list(0, 100000);
            const apps = (res && res.apps) || [];

            const configured = new Set();
            const appProviders = [];
            for (const app of apps) {
                if (app && app.provider) {
                    configured.add(app.provider);
                    appProviders.push([app.id, app.provider]);
                }
            }
            diag.oapp = Array.from(configured).sort();

            const inUse = new Set();
            let oauthAccounts = 0;
            if (appProviders.length) {
                const multi = redis.multi();
                for (const [id] of appProviders) {
                    multi.scard(`${REDIS_PREFIX}oapp:a:${id}`);
                }
                const counts = await multi.exec();
                for (let i = 0; i < appProviders.length; i++) {
                    const entry = counts[i];
                    const count = (entry && !entry[0] && Number(entry[1])) || 0;
                    oauthAccounts += count;
                    if (count > 0) {
                        inUse.add(appProviders[i][1]);
                    }
                }
            }
            if (rawAccounts > oauthAccounts) {
                inUse.add('imap');
            }
            diag.prov = Array.from(inUse).sort();
        });

        // Exercised-usage signals from the existing event counters.
        await safe(async () => {
            const counters = (await getCounterValues(redis, USE_WINDOW_SECONDS)) || {};
            const use = [];
            if (counters['events:messageNew'] > 0) use.push('recv');
            if (counters['submit:success'] > 0) use.push('send');
            if (counters['webhooks:success'] > 0) use.push('wh');
            if (counters['apiCall:success'] > 0) use.push('api');
            diag.use = use.sort();
        });

        // Deprecation watchlist (presence of legacy/candidate-for-removal features).
        const dep = [];
        if (on('documentStoreEnabled')) dep.push('documentStore');
        if (documentStoreFeatureEnabled) dep.push('documentStoreGate');
        if (on('documentStoreGenerateEmbeddings')) dep.push('ds_embed');
        if (on('documentStorePreProcessingEnabled')) dep.push('ds_preproc');
        if (on('gmailEnabled') || on('outlookEnabled') || on('mailRuEnabled')) dep.push('legacyOauth');
        if (on('trackSentMessages')) dep.push('trackSent');
        if (EE_DOCKER_LEGACY) dep.push('dockerLegacy');
        await safe(async () => {
            const ids = await redis.smembers(`${REDIS_PREFIX}wh:i`);
            if (ids && ids.length && ids.length <= WH_SCAN_LIMIT) {
                const bufs = await redis.hmgetBuffer(
                    `${REDIS_PREFIX}wh:c`,
                    ids.map(id => `${id}:content`)
                );
                for (const buf of bufs || []) {
                    if (!buf || !buf.length) {
                        continue;
                    }
                    try {
                        const content = msgpack.decode(buf);
                        if (content && (content.fn || content.map)) {
                            dep.push('whSubscript');
                            break;
                        }
                    } catch (err) {
                        // undecodable entry, skip
                    }
                }
            }
        });
        diag.dep = dep.sort();

        // Enabled EENGINE_FEATURE_* flags (already sorted).
        diag.flags = (await safe(() => featureFlags.listEnabled())) || [];

        // Runtime context.
        diag.dist = installChannel();
        diag.node = process.versions.node;
        diag.arch = process.arch;

        const fh = crypto.createHash('sha256').update(stableStringify(diag)).digest('hex').slice(0, 12);

        return { fh, diag };
    } catch (err) {
        if (logger) {
            logger.error({ msg: 'Beacon collection failed', err });
        }
        return null;
    }
}

// Collect the snapshot (time-boxed) and decide what to attach to the license request body.
// Always attaches the digest `fh`; attaches the full `diag` only when the digest changed since the
// last accepted send or the 30-day heartbeat is due. Best-effort: never throws.
async function attachBeacon(body, { redis, logger, now }) {
    try {
        const beacon = await withTimeout(collectBeacon({ redis, logger }), COLLECT_TIMEOUT_MS);
        if (!beacon || !beacon.fh) {
            return;
        }
        body.fh = beacon.fh;

        const [storedHash, bft] = await redis.hmget(`${REDIS_PREFIX}settings`, ['bfh', 'bft']);
        const lastFull = parseInt(bft || '0', 16) || 0;
        if (beacon.fh !== storedHash || now - lastFull > FULL_RESEND_INTERVAL_MS) {
            body.diag = beacon.diag;
        }
    } catch (err) {
        if (logger) {
            logger.error({ msg: 'License beacon collection failed', err });
        }
    }
}

// Persist the send-on-change markers after a successful validation. `needFull` (from the server)
// forces a full resend on the next cycle when the server has the digest but not the snapshot.
// Best-effort: never throws.
async function persistBeaconMarkers({ redis, logger, body, now, needFull }) {
    try {
        if (body.fh) {
            await redis.hset(`${REDIS_PREFIX}settings`, 'bfh', body.fh);
            if (body.diag) {
                await redis.hset(`${REDIS_PREFIX}settings`, 'bft', now.toString(16));
            }
        }
        if (needFull) {
            await redis.hdel(`${REDIS_PREFIX}settings`, 'bfh');
        }
    } catch (err) {
        if (logger) {
            logger.error({ msg: 'Failed to persist license beacon markers', err });
        }
    }
}

module.exports = { collectBeacon, attachBeacon, persistBeaconMarkers, withTimeout, tier, stableStringify };
