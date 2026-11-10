'use strict';

/**
 * What the online subscription check decides, as pure functions: server.js applies the result to
 * Redis and to the workers, and the unit tests pin every rule here.
 *
 * State kept in the settings hash:
 *   subexp  - the deadline (ms) until which EmailEngine keeps working while the subscription behind
 *             its license is not in good standing
 *   subsusp - JSON describing a suspension: the deadline has passed and the license server asked to
 *             keep the key (keepLicense), so the workers stop but the key stays registered
 *
 * The license server (postalsys.com) decides the deadline and sends it as graceUntil: 7 days after a
 * failed monthly renewal, 28 after a yearly one, none after a cancellation. A server that sends no
 * graceUntil gets the 28 days counted from the first refusal, and without keepLicense the key is
 * removed when they run out, which is how every earlier release behaved.
 */

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

// Days of service after the first refusal when the server names no deadline
const LEGACY_GRACE = 28 * DAY;
// How often the subscription is checked online: daily, and hourly while it is not in good standing
const CHECK_INTERVAL = DAY;
const OVERDUE_CHECK_INTERVAL = HOUR;
// The furthest a successful answer may postpone the next check
const MAX_LICENSE_CHECK_DELAY = 30 * DAY;
// A startup check is skipped when the last successful one is this recent
const STARTUP_CHECK_FRESHNESS = HOUR;

const toTime = value => {
    if (value === null || value === undefined || value === '') {
        return null;
    }
    // Redis hands back a stored millisecond value as a string of digits
    const time = typeof value === 'number' ? value : /^\d+$/.test(value) ? Number(value) : new Date(value).getTime();
    return Number.isFinite(time) ? time : null;
};

/**
 * Parses the stored subsusp value
 * @param {string|null} raw
 * @returns {Object|null} { code, error, since, overdueSince, endedAt } or null
 */
function parseSuspension(raw) {
    if (!raw) {
        return null;
    }
    try {
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (err) {
        return null;
    }
}

/**
 * Is a license one whose validity depends on a subscription, and so is checked online?
 * Trial and other time-limited licenses carry their own expiry, lifetime ones never lapse.
 * @param {Object} details - checkLicense() output
 * @returns {boolean}
 */
const isSubscriptionLicense = details => !!details && !details.expires && !details.lt && !details.trial;

/**
 * How long to wait between online checks
 * @param {Object} state - { subexp, subsusp } as stored
 * @returns {number} milliseconds
 */
const checkInterval = state => (state && (toTime(state.subexp) || state.subsusp) ? OVERDUE_CHECK_INTERVAL : CHECK_INTERVAL);

/**
 * What one answer of the license server changes
 * @param {Object} result
 * @param {boolean} result.ok - the answer was 2xx
 * @param {Object} result.data - its JSON body
 * @param {number} result.now
 * @param {number|null} result.subexp - the stored deadline
 * @returns {Object} { clear, resume, subexp, suspend, removeLicense, nextCheck }: clear drops subexp
 *   and subsusp; resume drops subsusp only (the deadline is in the future again); subexp is a deadline
 *   to store; suspend is the subsusp record to store; removeLicense is the legacy outcome; nextCheck is
 *   when the next online check is due (ms), or null to leave it
 */
function decide({ ok, data, now, subexp }) {
    data = data || {};

    if (ok) {
        const validatedUntil = toTime(data.validatedUntil);
        return {
            clear: true,
            resume: true,
            subexp: null,
            suspend: null,
            removeLicense: false,
            nextCheck: validatedUntil ? Math.min(now + MAX_LICENSE_CHECK_DELAY, validatedUntil) : null
        };
    }

    // A refusal without invalidate is not about the subscription (bad input, a server error):
    // nothing changes, EmailEngine never stops over the license server's own trouble
    if (!data.invalidate) {
        return { clear: false, resume: false, subexp: null, suspend: null, removeLicense: false, nextCheck: null };
    }

    const stored = toTime(subexp);
    const deadline = toTime(data.graceUntil) || stored || now + LEGACY_GRACE;

    if (deadline > now) {
        // inside the window: working, even if a stored suspension said otherwise (the server's
        // deadline is the one that counts, and it can move later)
        return { clear: false, resume: true, subexp: deadline, suspend: null, removeLicense: false, nextCheck: now + OVERDUE_CHECK_INTERVAL };
    }

    if (!data.keepLicense) {
        return { clear: false, resume: false, subexp: null, suspend: null, removeLicense: true, nextCheck: null };
    }

    return {
        clear: false,
        resume: false,
        subexp: deadline,
        suspend: {
            code: typeof data.code === 'string' ? data.code.slice(0, 64) : 'SubscriptionInactive',
            error: typeof data.error === 'string' ? data.error.slice(0, 256) : 'Subscription inactive',
            since: new Date(deadline).toISOString(),
            overdueSince: toTime(data.overdueSince) ? new Date(toTime(data.overdueSince)).toISOString() : null,
            endedAt: toTime(data.endedAt) ? new Date(toTime(data.endedAt)).toISOString() : null
        },
        removeLicense: false,
        nextCheck: now + OVERDUE_CHECK_INTERVAL
    };
}

/**
 * The suspension a stored deadline implies on its own: when it has passed and no suspension is
 * recorded yet (the license server could not be asked, or the deadline ran out while EmailEngine
 * was not running), EmailEngine suspends itself and lets the next answer of the server decide
 * @param {number|string|null} subexp - the stored deadline
 * @param {string|null} subsusp - the stored suspension
 * @param {number} now
 * @returns {Object|null} the suspension record to store, or null
 */
function expiredSuspension(subexp, subsusp, now) {
    const deadline = toTime(subexp);
    if (parseSuspension(subsusp) || !deadline || deadline > now) {
        return null;
    }
    return { code: 'SubscriptionInactive', error: 'Subscription inactive', since: new Date(deadline).toISOString() };
}

/**
 * What a start of EmailEngine does before any worker runs
 * @param {Object} input
 * @param {Object|false} input.details - the loaded license (checkLicense() output), or false
 * @param {number|string|null} input.subexp - the stored deadline
 * @param {string|null} input.subsusp - the stored suspension
 * @param {number|string|null} input.subcheck - when the last online check ran (ms)
 * @param {number} input.now
 * @returns {Object} { suspension, checkNow }: suspension is the record to start suspended with, or
 *   null; checkNow asks for an online check right away instead of in 20 minutes
 */
function startupPlan({ details, subexp, subsusp, subcheck, now }) {
    if (!isSubscriptionLicense(details)) {
        return { suspension: null, checkNow: false };
    }

    const deadline = toTime(subexp);
    const suspension = parseSuspension(subsusp) || expiredSuspension(subexp, subsusp, now);

    const lastCheck = toTime(subcheck);
    const recentlyChecked = !!lastCheck && now - lastCheck < STARTUP_CHECK_FRESHNESS;
    // a restart loop costs one call an hour, whatever the reason to check
    const checkNow = (!!suspension || !!deadline || details.billing === 'monthly') && !recentlyChecked;

    return { suspension, checkNow };
}

/**
 * Does registering a license keep the stored subscription state? Only when it is the key already
 * registered: registering the same file again (by hand, through the API, or at every start from a
 * license file or EENGINE_PREPARED_LICENSE) must not lift a suspension. A different key starts clean,
 * and the online check that follows registration decides its standing.
 * @param {string|null} storedKey - key of the license currently registered
 * @param {string} newKey - key of the license being registered
 * @returns {boolean}
 */
const keepsSubscriptionState = (storedKey, newKey) => !!storedKey && !!newKey && storedKey === newKey;

/**
 * The subscription state as the license page and the API report it
 * @param {Object} input - { subexp, suspension, now }
 * @returns {Object|null} { status, code, error, since, until, days } or null when in good standing;
 *   days is how many whole days remain until `until` (0 once it has passed)
 */
function subscriptionView({ subexp, suspension, now }) {
    let view = null;
    if (suspension) {
        view = {
            status: 'suspended',
            code: suspension.code || null,
            error: suspension.error || null,
            since: suspension.overdueSince || suspension.endedAt || suspension.since || null,
            until: suspension.since || null
        };
    } else if (toTime(subexp)) {
        const deadline = toTime(subexp);
        view = { status: deadline > now ? 'overdue' : 'suspended', code: null, error: null, since: null, until: new Date(deadline).toISOString() };
    }
    if (view) {
        const until = toTime(view.until);
        view.days = until ? Math.max(Math.ceil((until - now) / DAY), 0) : 0;
    }
    return view;
}

/**
 * Is the subscription behind a license reported as suspended?
 * @param {Object} licenseInfo - the `license` command's answer
 * @returns {boolean}
 */
const isSuspended = licenseInfo => !!(licenseInfo && licenseInfo.subscription && licenseInfo.subscription.status === 'suspended');

module.exports = {
    decide,
    startupPlan,
    expiredSuspension,
    checkInterval,
    subscriptionView,
    isSuspended,
    parseSuspension,
    isSubscriptionLicense,
    keepsSubscriptionState,
    LEGACY_GRACE,
    CHECK_INTERVAL,
    OVERDUE_CHECK_INTERVAL,
    MAX_LICENSE_CHECK_DELAY
};
