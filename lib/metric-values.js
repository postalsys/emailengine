'use strict';

// Values the main thread publishes as Prometheus gauges, computed from its state without touching
// the gauges themselves, so they can be tested without starting server.js.

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * The license_days_remaining gauge value.
 *
 * @param {Object} licenseInfo - the main thread's license state (`active`, `details`)
 * @param {number} now - current time in milliseconds
 * @returns {number} days left on a time-limited license (never below 0), -1 for a lifetime or
 *   subscription license, 0 when no license is active
 */
function licenseDaysRemaining(licenseInfo, now) {
    if (!licenseInfo.active || !licenseInfo.details) {
        // No active license
        return 0;
    }

    if (licenseInfo.details.lt) {
        // Lifetime license
        return -1;
    }

    if (licenseInfo.details.expires) {
        // Time-limited license
        let expiresAt = new Date(licenseInfo.details.expires).getTime();
        return Math.max(0, Math.ceil((expiresAt - now) / DAY_MS));
    }

    // Subscription license (no fixed expiry)
    return -1;
}

/**
 * Worker thread counts for the threads gauge, split by type and by whether the thread came
 * online within the recent window, plus how many threads failed to answer a resource reading.
 *
 * @param {Array<Object>} threadsInfo - thread readings (`type`, `online`, `resourceUsageError`)
 * @param {number} now - current time in milliseconds
 * @param {number} recentWindow - how long after coming online a thread counts as recent, in ms
 * @returns {{threadCounts: Map<string, number>, unresponsiveCount: number}} counts keyed
 *   `<type>_recent` or `<type>_total`, in first-seen order
 */
function countThreads(threadsInfo, now, recentWindow) {
    let threadCounts = new Map();
    let unresponsiveCount = 0;

    for (let workerThreadInfo of threadsInfo || []) {
        let key = workerThreadInfo.type;
        let metricKey = `${key}_total`;

        // Check if thread is recent (started within the recent window)
        let recent = now - workerThreadInfo.online < recentWindow;
        if (recent) {
            metricKey = `${key}_recent`;
        }

        if (!threadCounts.has(metricKey)) {
            threadCounts.set(metricKey, 1);
        } else {
            threadCounts.set(metricKey, threadCounts.get(metricKey) + 1);
        }

        // Count unresponsive workers
        if (workerThreadInfo.resourceUsageError && workerThreadInfo.resourceUsageError.unresponsive) {
            unresponsiveCount++;
        }
    }

    return { threadCounts, unresponsiveCount };
}

module.exports = { licenseDaysRemaining, countThreads };
