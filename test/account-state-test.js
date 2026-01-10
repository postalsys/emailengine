'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    ACCOUNT_STATES,
    VALID_STATES,
    BYPASS_RUN_INDEX_STATES,
    calculateEffectiveState,
    validateAccountState,
    getDisplayState,
    formatLastError
} = require('../lib/account/account-state');

test('Account State tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    // Constants tests
    await t.test('ACCOUNT_STATES contains all expected states', async () => {
        assert.strictEqual(ACCOUNT_STATES.INIT, 'init');
        assert.strictEqual(ACCOUNT_STATES.UNSET, 'unset');
        assert.strictEqual(ACCOUNT_STATES.CONNECTED, 'connected');
        assert.strictEqual(ACCOUNT_STATES.CONNECTING, 'connecting');
        assert.strictEqual(ACCOUNT_STATES.SYNCING, 'syncing');
        assert.strictEqual(ACCOUNT_STATES.AUTHENTICATION_ERROR, 'authenticationError');
        assert.strictEqual(ACCOUNT_STATES.CONNECT_ERROR, 'connectError');
    });

    await t.test('VALID_STATES contains operational states', async () => {
        assert.ok(VALID_STATES.includes(ACCOUNT_STATES.CONNECTED));
        assert.ok(VALID_STATES.includes(ACCOUNT_STATES.CONNECTING));
        assert.ok(VALID_STATES.includes(ACCOUNT_STATES.SYNCING));
        assert.strictEqual(VALID_STATES.length, 3);
    });

    await t.test('BYPASS_RUN_INDEX_STATES contains init and unset', async () => {
        assert.ok(BYPASS_RUN_INDEX_STATES.includes(ACCOUNT_STATES.INIT));
        assert.ok(BYPASS_RUN_INDEX_STATES.includes(ACCOUNT_STATES.UNSET));
        assert.strictEqual(BYPASS_RUN_INDEX_STATES.length, 2);
    });

    // calculateEffectiveState tests
    await t.test('calculateEffectiveState() returns current state when runIndex is falsy', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 5 };

        assert.strictEqual(calculateEffectiveState(accountData, 0), ACCOUNT_STATES.CONNECTED);
        assert.strictEqual(calculateEffectiveState(accountData, null), ACCOUNT_STATES.CONNECTED);
        assert.strictEqual(calculateEffectiveState(accountData, undefined), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('calculateEffectiveState() returns current state when runIndex <= accountRunIndex', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 10 };

        assert.strictEqual(calculateEffectiveState(accountData, 5), ACCOUNT_STATES.CONNECTED);
        assert.strictEqual(calculateEffectiveState(accountData, 10), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('calculateEffectiveState() returns current state for INIT bypass state', async () => {
        const accountData = { state: ACCOUNT_STATES.INIT, runIndex: 5 };

        assert.strictEqual(calculateEffectiveState(accountData, 15), ACCOUNT_STATES.INIT);
    });

    await t.test('calculateEffectiveState() returns current state for UNSET bypass state', async () => {
        const accountData = { state: ACCOUNT_STATES.UNSET, runIndex: 5 };

        assert.strictEqual(calculateEffectiveState(accountData, 15), ACCOUNT_STATES.UNSET);
    });

    await t.test('calculateEffectiveState() returns current state for API accounts', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 5, isApi: true };

        assert.strictEqual(calculateEffectiveState(accountData, 15), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('calculateEffectiveState() returns INIT when account not processed by current worker', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 5, isApi: false };

        assert.strictEqual(calculateEffectiveState(accountData, 15), ACCOUNT_STATES.INIT);
    });

    await t.test('calculateEffectiveState() handles authentication error state correctly', async () => {
        const accountData = { state: ACCOUNT_STATES.AUTHENTICATION_ERROR, runIndex: 5 };

        // When runIndex > accountRunIndex and not a bypass state, should return INIT
        assert.strictEqual(calculateEffectiveState(accountData, 15), ACCOUNT_STATES.INIT);
    });

    // validateAccountState tests
    await t.test('validateAccountState() does not throw for CONNECTED state', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED };
        assert.doesNotThrow(() => validateAccountState(accountData));
    });

    await t.test('validateAccountState() does not throw for CONNECTING state', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTING };
        assert.doesNotThrow(() => validateAccountState(accountData));
    });

    await t.test('validateAccountState() does not throw for SYNCING state', async () => {
        const accountData = { state: ACCOUNT_STATES.SYNCING };
        assert.doesNotThrow(() => validateAccountState(accountData));
    });

    await t.test('validateAccountState() throws for INIT state', async () => {
        const accountData = { state: ACCOUNT_STATES.INIT };

        try {
            validateAccountState(accountData);
            assert.fail('Should have thrown');
        } catch (err) {
            assert.strictEqual(err.output.statusCode, 503);
            assert.strictEqual(err.output.payload.code, 'NotYetConnected');
            assert.strictEqual(err.output.payload.state, ACCOUNT_STATES.INIT);
        }
    });

    await t.test('validateAccountState() throws for AUTHENTICATION_ERROR state', async () => {
        const accountData = { state: ACCOUNT_STATES.AUTHENTICATION_ERROR };

        try {
            validateAccountState(accountData);
            assert.fail('Should have thrown');
        } catch (err) {
            assert.strictEqual(err.output.statusCode, 503);
            assert.strictEqual(err.output.payload.code, 'AuthenticationFails');
            assert.strictEqual(err.output.payload.state, ACCOUNT_STATES.AUTHENTICATION_ERROR);
        }
    });

    await t.test('validateAccountState() throws for CONNECT_ERROR state', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECT_ERROR };

        try {
            validateAccountState(accountData);
            assert.fail('Should have thrown');
        } catch (err) {
            assert.strictEqual(err.output.statusCode, 503);
            assert.strictEqual(err.output.payload.code, 'ConnectionError');
            assert.strictEqual(err.output.payload.state, ACCOUNT_STATES.CONNECT_ERROR);
        }
    });

    await t.test('validateAccountState() throws for UNSET state', async () => {
        const accountData = { state: ACCOUNT_STATES.UNSET };

        try {
            validateAccountState(accountData);
            assert.fail('Should have thrown');
        } catch (err) {
            assert.strictEqual(err.output.statusCode, 503);
            assert.strictEqual(err.output.payload.code, 'NotSyncing');
            assert.strictEqual(err.output.payload.state, ACCOUNT_STATES.UNSET);
        }
    });

    await t.test('validateAccountState() throws for unknown state', async () => {
        const accountData = { state: 'unknownState' };

        try {
            validateAccountState(accountData);
            assert.fail('Should have thrown');
        } catch (err) {
            assert.strictEqual(err.output.statusCode, 503);
            assert.strictEqual(err.output.payload.code, 'NoAvailable');
            assert.strictEqual(err.output.payload.state, 'unknownState');
        }
    });

    // getDisplayState tests
    await t.test('getDisplayState() returns current state when runIndex is falsy', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 5 };

        assert.strictEqual(getDisplayState(accountData, 0), ACCOUNT_STATES.CONNECTED);
        assert.strictEqual(getDisplayState(accountData, null), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('getDisplayState() returns current state when runIndex <= accountRunIndex', async () => {
        const accountData = { state: ACCOUNT_STATES.SYNCING, runIndex: 10 };

        assert.strictEqual(getDisplayState(accountData, 5), ACCOUNT_STATES.SYNCING);
        assert.strictEqual(getDisplayState(accountData, 10), ACCOUNT_STATES.SYNCING);
    });

    await t.test('getDisplayState() returns current state for bypass states', async () => {
        const initAccount = { state: ACCOUNT_STATES.INIT, runIndex: 5 };
        const unsetAccount = { state: ACCOUNT_STATES.UNSET, runIndex: 5 };

        assert.strictEqual(getDisplayState(initAccount, 15), ACCOUNT_STATES.INIT);
        assert.strictEqual(getDisplayState(unsetAccount, 15), ACCOUNT_STATES.UNSET);
    });

    await t.test('getDisplayState() returns current state for API accounts', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 5, isApi: true };

        assert.strictEqual(getDisplayState(accountData, 15), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('getDisplayState() returns INIT when not processed by current worker', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 5, isApi: false };

        assert.strictEqual(getDisplayState(accountData, 15), ACCOUNT_STATES.INIT);
    });

    // formatLastError tests
    await t.test('formatLastError() returns null for CONNECTED state', async () => {
        const accountData = {
            state: ACCOUNT_STATES.CONNECTED,
            lastErrorState: { error: 'some error', time: Date.now() }
        };

        assert.strictEqual(formatLastError(accountData), null);
    });

    await t.test('formatLastError() returns null when no lastErrorState', async () => {
        const accountData = { state: ACCOUNT_STATES.AUTHENTICATION_ERROR };

        assert.strictEqual(formatLastError(accountData), null);
    });

    await t.test('formatLastError() returns null for empty lastErrorState', async () => {
        const accountData = {
            state: ACCOUNT_STATES.AUTHENTICATION_ERROR,
            lastErrorState: {}
        };

        assert.strictEqual(formatLastError(accountData), null);
    });

    await t.test('formatLastError() returns lastErrorState for error states', async () => {
        const errorState = { error: 'Authentication failed', time: Date.now(), code: 'AUTH_FAIL' };
        const accountData = {
            state: ACCOUNT_STATES.AUTHENTICATION_ERROR,
            lastErrorState: errorState
        };

        assert.deepStrictEqual(formatLastError(accountData), errorState);
    });

    await t.test('formatLastError() returns lastErrorState for CONNECT_ERROR', async () => {
        const errorState = { error: 'Connection timeout', time: Date.now() };
        const accountData = {
            state: ACCOUNT_STATES.CONNECT_ERROR,
            lastErrorState: errorState
        };

        assert.deepStrictEqual(formatLastError(accountData), errorState);
    });

    await t.test('formatLastError() returns lastErrorState for INIT state', async () => {
        const errorState = { error: 'Initialization pending', time: Date.now() };
        const accountData = {
            state: ACCOUNT_STATES.INIT,
            lastErrorState: errorState
        };

        assert.deepStrictEqual(formatLastError(accountData), errorState);
    });
});
