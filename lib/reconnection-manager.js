'use strict';

/**
 * ReconnectionManager - Helper class for consistent reconnection behavior
 * Provides capped exponential backoff with jitter for reconnection attempts
 */
class ReconnectionManager {
    constructor(options = {}) {
        this.baseDelay = options.baseDelay || 2000;
        this.maxDelay = options.maxDelay || 30000;
        this.backoffMultiplier = options.backoffMultiplier || 1.5;
        this.jitterMs = options.jitterMs || 1000;
        this.attempts = 0;
        this.currentDelay = this.baseDelay;
        this.logger = options.logger;
    }

    /**
     * Calculate the next reconnection delay with exponential backoff and jitter
     * @returns {number} Delay in milliseconds before next reconnection attempt
     */
    getNextDelay() {
        // Calculate delay with exponential backoff, capped at maxDelay
        this.currentDelay = Math.min(this.maxDelay, this.baseDelay * Math.pow(this.backoffMultiplier, Math.min(this.attempts, 10)));

        // Add jitter to prevent synchronized reconnection storms
        const jitter = Math.random() * this.jitterMs;
        const totalDelay = this.currentDelay + jitter;

        this.attempts++;

        if (this.logger) {
            this.logger.debug({
                msg: 'Calculated reconnection delay',
                attempt: this.attempts,
                delay: totalDelay,
                baseDelay: this.currentDelay
            });
        }

        return totalDelay;
    }

    /**
     * Reset the reconnection manager state (typically called on successful connection)
     */
    reset() {
        this.attempts = 0;
        this.currentDelay = this.baseDelay;

        if (this.logger) {
            this.logger.debug({
                msg: 'Reconnection manager reset'
            });
        }
    }

    /**
     * Wait for the calculated delay and then execute the reconnection function
     * @param {Function} reconnectFn - The async function to execute for reconnection
     * @returns {Promise} Result of the reconnection function
     */
    async waitAndReconnect(reconnectFn) {
        const delay = this.getNextDelay();

        if (this.logger) {
            this.logger.info({
                msg: 'Waiting before reconnection attempt',
                delay,
                attempt: this.attempts
            });
        }

        await new Promise(resolve => setTimeout(resolve, delay));

        try {
            const result = await reconnectFn();
            this.reset(); // Reset on success
            return result;
        } catch (err) {
            // Don't reset, keep incrementing delay
            if (this.logger) {
                this.logger.error({
                    msg: 'Reconnection attempt failed',
                    attempt: this.attempts,
                    err
                });
            }
            throw err;
        }
    }

    /**
     * Get current state of the manager
     * @returns {Object} Current state including attempts and delay
     */
    getState() {
        return {
            attempts: this.attempts,
            currentDelay: this.currentDelay,
            nextDelay: this.getNextDelay()
        };
    }
}

module.exports = { ReconnectionManager };
