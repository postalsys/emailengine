'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const exitWhenStandalone = require('./helpers/exit-standalone');

const {
    ACCOUNT_STATES,
    VALID_STATES,
    BYPASS_RUN_INDEX_STATES,
    calculateEffectiveState,
    validateAccountState,
    getDisplayState,
    isCurrentRunState,
    formatLastError
} = require('../lib/account/account-state');

test('Account State tests', async t => {
    t.after(() => {
        exitWhenStandalone();
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

    // calculateEffectiveState tests. The claiming instance records its run as ownerRun, the
    // connection records its run as runIndex with every state it reaches (lib/cluster/)
    await t.test('calculateEffectiveState() returns the stored state once the owning run wrote it', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 7, ownerRun: 7 };
        assert.strictEqual(calculateEffectiveState(accountData), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('calculateEffectiveState() returns INIT for an account claimed but not connected yet', async () => {
        // Claimed by run 9; the stored state is what run 7 left behind
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 7, ownerRun: 9 };
        assert.strictEqual(calculateEffectiveState(accountData), ACCOUNT_STATES.INIT);
    });

    await t.test('calculateEffectiveState() does not depend on run numbers growing across instances', async () => {
        // An instance started earlier (a lower run) takes over from one started later
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 12, ownerRun: 4 };
        assert.strictEqual(calculateEffectiveState(accountData), ACCOUNT_STATES.INIT);
        assert.strictEqual(calculateEffectiveState(Object.assign({}, accountData, { runIndex: 4 })), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('calculateEffectiveState() takes the stored state of a record nobody claimed yet', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 5 };
        assert.strictEqual(calculateEffectiveState(accountData), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('calculateEffectiveState() returns current state for INIT and UNSET bypass states', async () => {
        assert.strictEqual(calculateEffectiveState({ state: ACCOUNT_STATES.INIT, runIndex: 5, ownerRun: 9 }), ACCOUNT_STATES.INIT);
        assert.strictEqual(calculateEffectiveState({ state: ACCOUNT_STATES.UNSET, runIndex: 5, ownerRun: 9 }), ACCOUNT_STATES.UNSET);
    });

    await t.test('calculateEffectiveState() returns current state for API accounts', async () => {
        const accountData = { state: ACCOUNT_STATES.CONNECTED, runIndex: 5, ownerRun: 9, isApi: true };
        assert.strictEqual(calculateEffectiveState(accountData), ACCOUNT_STATES.CONNECTED);
    });

    await t.test('calculateEffectiveState() reports an error state of an earlier run as INIT', async () => {
        const accountData = { state: ACCOUNT_STATES.AUTHENTICATION_ERROR, runIndex: 5, ownerRun: 15 };
        assert.strictEqual(calculateEffectiveState(accountData), ACCOUNT_STATES.INIT);
    });

    await t.test('isCurrentRunState() compares runs as numbers', async () => {
        assert.strictEqual(isCurrentRunState({ runIndex: '7', ownerRun: 7 }), true);
        assert.strictEqual(isCurrentRunState({ runIndex: 0, ownerRun: 7 }), false);
        assert.strictEqual(isCurrentRunState({}), true);
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
    await t.test('getDisplayState() follows calculateEffectiveState()', async () => {
        assert.strictEqual(getDisplayState({ state: ACCOUNT_STATES.SYNCING, runIndex: 10, ownerRun: 10 }), ACCOUNT_STATES.SYNCING);
        assert.strictEqual(getDisplayState({ state: ACCOUNT_STATES.CONNECTED, runIndex: 5, ownerRun: 15 }), ACCOUNT_STATES.INIT);
        assert.strictEqual(getDisplayState({ state: ACCOUNT_STATES.UNSET, runIndex: 5, ownerRun: 15 }), ACCOUNT_STATES.UNSET);
        assert.strictEqual(getDisplayState({ state: ACCOUNT_STATES.CONNECTED, runIndex: 5, ownerRun: 15, isApi: true }), ACCOUNT_STATES.CONNECTED);
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
