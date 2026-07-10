'use strict';

// Shared capped exponential backoff counter for IMAP reconnection scheduling.
// Pure delay math - the consumers own the timers and decide when a setup
// counts as validated (reset()).

// Exponent clamp so the intermediate float can not blow up on a long outage;
// with the delay cap applied the clamp itself never changes the resulting
// delay for the parameter sets in use
const MAX_ATTEMPT_EXPONENT = 10;

class ReconnectBackoff {
    constructor(opts) {
        opts = opts || {};
        this.baseDelay = opts.baseDelay || 2000; // first computed delay (before jitter)
        this.maxDelay = opts.maxDelay || 30000;
        this.factor = opts.factor || 1.5;
        this.jitter = opts.jitter || 0; // random 0..jitter ms added after the cap
        this.attempts = 0;
    }

    /**
     * Returns the next scheduling delay and increments the attempt counter:
     * min(maxDelay, baseDelay * factor^attempts) plus random jitter
     * @returns {number} Delay in milliseconds
     */
    nextDelay() {
        const delay = Math.min(this.maxDelay, this.baseDelay * Math.pow(this.factor, Math.min(this.attempts, MAX_ATTEMPT_EXPONENT)));
        this.attempts++;
        return this.jitter ? delay + Math.random() * this.jitter : delay;
    }

    reset() {
        this.attempts = 0;
    }
}

module.exports = { ReconnectBackoff };
