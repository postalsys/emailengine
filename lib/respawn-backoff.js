'use strict';

// Respawn pacing for supervised worker threads.
//
// A worker that dies deterministically (bad config, an unsatisfiable dependency, a crash on
// startup) used to be respawned on a flat 1s timer forever: roughly one thread start per second,
// indefinitely, pinning a core and burying every other log line under the same repeating stack.
//
// This is pacing, not a circuit breaker. Respawning never stops and is never blocked by another
// worker's failures - the delay only grows while a given worker type keeps dying quickly, and a
// worker that stays up resets its own type immediately.

const DEFAULT_BASE_DELAY = 1000;
const DEFAULT_MAX_DELAY = 60 * 1000;

// How long a worker must survive before its start counts as successful. Longer than any plausible
// startup crash, shorter than any real workload, so a genuine crash loop cannot look healthy.
const DEFAULT_STABLE_UPTIME = 60 * 1000;

const DEFAULT_JITTER = 0.2;

/**
 * Tracks per-type crash streaks and derives how long to wait before the next respawn.
 */
class RespawnTracker {
    constructor(opts) {
        const {
            baseDelay = DEFAULT_BASE_DELAY,
            maxDelay = DEFAULT_MAX_DELAY,
            stableUptime = DEFAULT_STABLE_UPTIME,
            jitter = DEFAULT_JITTER,
            random = Math.random
        } = opts || {};

        this.baseDelay = baseDelay;
        this.maxDelay = maxDelay;
        this.stableUptime = stableUptime;
        this.jitter = jitter;
        this.random = random;

        // worker type -> count of consecutive short-lived exits
        this.failures = new Map();
    }

    /**
     * Records that a worker of the given type exited and returns the delay before respawning it.
     *
     * @param {string} type - Worker type (imap, api, webhooks, ...)
     * @param {number} uptimeMs - How long the worker had been running
     * @returns {number} Milliseconds to wait before respawning
     */
    recordExit(type, uptimeMs) {
        if (uptimeMs >= this.stableUptime) {
            // The worker did real work before dying, so this is not a crash loop. Start over so a
            // long-lived worker that finally crashes restarts as promptly as a fresh one.
            this.failures.delete(type);
            return this.delayFor(1);
        }

        const failures = (this.failures.get(type) || 0) + 1;
        this.failures.set(type, failures);

        return this.delayFor(failures);
    }

    /**
     * Delay for the nth consecutive failure. The first failure keeps the historical 1s delay.
     * @param {number} failures - Consecutive short-lived exits, 1 based
     * @returns {number} Milliseconds to wait
     */
    delayFor(failures) {
        const delay = Math.min(this.baseDelay * Math.pow(2, failures - 1), this.maxDelay);

        // Spread respawns so a fleet-wide crash (Redis went away) does not come back in lockstep
        const spread = 1 - this.jitter + this.jitter * 2 * this.random();

        return Math.round(delay * spread);
    }

    /**
     * Consecutive short-lived exits recorded for a type, for logging.
     * @param {string} type - Worker type
     * @returns {number} Current streak
     */
    streakFor(type) {
        return this.failures.get(type) || 0;
    }
}

module.exports = {
    RespawnTracker,
    DEFAULT_BASE_DELAY,
    DEFAULT_MAX_DELAY,
    DEFAULT_STABLE_UPTIME
};
