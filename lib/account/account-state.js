'use strict';

const Boom = require('@hapi/boom');
const { REDIS_PREFIX } = require('../consts');

// Account state constants
const ACCOUNT_STATES = {
    INIT: 'init',
    UNSET: 'unset',
    CONNECTED: 'connected',
    CONNECTING: 'connecting',
    SYNCING: 'syncing',
    AUTHENTICATION_ERROR: 'authenticationError',
    CONNECT_ERROR: 'connectError'
};

// States that indicate the account is operational
const VALID_STATES = [ACCOUNT_STATES.CONNECTED, ACCOUNT_STATES.CONNECTING, ACCOUNT_STATES.SYNCING];

// States that bypass runIndex checking
const BYPASS_RUN_INDEX_STATES = [ACCOUNT_STATES.INIT, ACCOUNT_STATES.UNSET];

/**
 * Calculates the effective account state based on runIndex and current state
 * @param {Object} accountData - The account data object
 * @param {number} runIndex - Current run index from the worker
 * @returns {string} The effective state value
 */
function calculateEffectiveState(accountData, runIndex) {
    const currentState = accountData.state;
    const accountRunIndex = accountData.runIndex;
    const isApiAccount = accountData.isApi;

    // API accounts and special states bypass runIndex checking
    if (!runIndex || runIndex <= accountRunIndex || BYPASS_RUN_INDEX_STATES.includes(currentState) || isApiAccount) {
        return currentState;
    }

    // Account hasn't been processed by current worker yet
    return ACCOUNT_STATES.INIT;
}

/**
 * Validates that an account is in a state suitable for operations
 * @param {Object} accountData - The account data object with state
 * @throws {Boom} When the account state is not valid for operations
 */
function validateAccountState(accountData) {
    if (VALID_STATES.includes(accountData.state)) {
        return;
    }

    let err;
    switch (accountData.state) {
        case ACCOUNT_STATES.INIT:
            err = new Error('Requested account is not yet initialized');
            err.code = 'NotYetConnected';
            break;

        case ACCOUNT_STATES.AUTHENTICATION_ERROR:
            err = new Error('Requested account can not be authenticated');
            err.code = 'AuthenticationFails';
            break;

        case ACCOUNT_STATES.CONNECT_ERROR:
            err = new Error('Can not establish server connection for requested account');
            err.code = 'ConnectionError';
            break;

        case ACCOUNT_STATES.UNSET:
            err = new Error('Syncing is disabled for the requested account');
            err.code = 'NotSyncing';
            break;

        default:
            err = new Error('Requested account currently not available');
            err.code = 'NoAvailable';
            break;
    }

    const error = Boom.boomify(err, { statusCode: 503 });
    if (accountData.state) {
        error.output.payload.state = accountData.state;
    }
    if (err.code) {
        error.output.payload.code = err.code;
    }
    throw error;
}

/**
 * Gets the account state from Redis
 * @param {Object} redis - Redis client
 * @param {string} account - Account ID
 * @returns {Promise<string|null>} The current state value
 */
async function getAccountState(redis, account) {
    const accountKey = `${REDIS_PREFIX}iad:${account}`;
    return await redis.hget(accountKey, 'state');
}

/**
 * Sets the account state in Redis
 * Only updates if the account exists
 * @param {Object} redis - Redis client
 * @param {string} account - Account ID
 * @param {string} state - New state value
 * @returns {Promise<boolean>} True if state was set
 */
async function setAccountState(redis, account, state) {
    const accountKey = `${REDIS_PREFIX}iad:${account}`;
    const result = await redis.hSetExists(accountKey, 'state', state);
    return result === 1;
}

/**
 * Gets the last error state for an account
 * @param {Object} redis - Redis client
 * @param {string} account - Account ID
 * @returns {Promise<Object|null>} Parsed error state object or null
 */
async function getLastErrorState(redis, account) {
    const accountKey = `${REDIS_PREFIX}iad:${account}`;
    const errorState = await redis.hget(accountKey, 'lastErrorState');

    if (!errorState) {
        return null;
    }

    try {
        return JSON.parse(errorState);
    } catch (err) {
        return null;
    }
}

/**
 * Sets the last error state for an account
 * @param {Object} redis - Redis client
 * @param {string} account - Account ID
 * @param {Object} errorData - Error state data
 * @returns {Promise<boolean>} True if error state was set
 */
async function setLastErrorState(redis, account, errorData) {
    const accountKey = `${REDIS_PREFIX}iad:${account}`;
    const result = await redis.hSetExists(accountKey, 'lastErrorState', JSON.stringify(errorData));
    return result === 1;
}

/**
 * Clears the last error state for an account
 * @param {Object} redis - Redis client
 * @param {string} account - Account ID
 * @returns {Promise<number>} Number of fields removed
 */
async function clearLastErrorState(redis, account) {
    const accountKey = `${REDIS_PREFIX}iad:${account}`;
    return await redis.hdel(accountKey, 'lastErrorState');
}

/**
 * Gets the connection count for a specific state
 * @param {Object} redis - Redis client
 * @param {string} account - Account ID
 * @param {string} state - State to get count for
 * @returns {Promise<number>} Connection count
 */
async function getStateCount(redis, account, state) {
    const accountKey = `${REDIS_PREFIX}iad:${account}`;
    const count = await redis.hget(accountKey, `state:count:${state}`);
    return parseInt(count, 10) || 0;
}

/**
 * Resets the connection count for a specific state
 * @param {Object} redis - Redis client
 * @param {string} account - Account ID
 * @param {string} state - State to reset count for
 * @returns {Promise<boolean>} True if count was reset
 */
async function resetStateCount(redis, account, state) {
    const accountKey = `${REDIS_PREFIX}iad:${account}`;
    const result = await redis.hset(accountKey, `state:count:${state}`, '0');
    return result >= 0;
}

/**
 * Formats the last error for API responses
 * Returns null if account is connected or no error exists
 * @param {Object} accountData - Account data object
 * @returns {Object|null} Formatted error object or null
 */
function formatLastError(accountData) {
    if (accountData.state === ACCOUNT_STATES.CONNECTED) {
        return null;
    }

    if (!accountData.lastErrorState || !Object.keys(accountData.lastErrorState).length) {
        return null;
    }

    return accountData.lastErrorState;
}

/**
 * Determines if account state should be reported as 'init' based on runIndex
 * Used for account listings when the worker hasn't processed the account yet
 * @param {Object} accountData - Account data with state and runIndex
 * @param {number} currentRunIndex - Current worker run index
 * @returns {string} Effective state for display
 */
function getDisplayState(accountData, currentRunIndex) {
    const currentState = accountData.state;
    const accountRunIndex = accountData.runIndex;
    const isApiAccount = accountData.isApi;

    if (!currentRunIndex || currentRunIndex <= accountRunIndex || BYPASS_RUN_INDEX_STATES.includes(currentState) || isApiAccount) {
        return currentState;
    }

    return ACCOUNT_STATES.INIT;
}

module.exports = {
    // Constants
    ACCOUNT_STATES,
    VALID_STATES,
    BYPASS_RUN_INDEX_STATES,

    // State calculation
    calculateEffectiveState,
    validateAccountState,
    getDisplayState,

    // Redis operations
    getAccountState,
    setAccountState,

    // Error state management
    getLastErrorState,
    setLastErrorState,
    clearLastErrorState,
    formatLastError,

    // State counters
    getStateCount,
    resetStateCount
};
