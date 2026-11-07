'use strict';

// EENGINE_PREPARED_PASSWORD rotation ended every admin session but left passkeys working, and a
// passkey signs in without the second factor. Every other way of replacing the admin password
// (the security page, `emailengine password`) already removed them.

const test = require('node:test');
const assert = require('node:assert').strict;

const { importPreparedPassword } = require('../lib/prepared-password');

function makeDeps(authData) {
    const state = { authData, cleared: [] };
    return {
        state,
        deps: {
            settings: {
                get: async key => (key === 'authData' ? state.authData : undefined),
                set: async (key, value) => {
                    state.authData = value;
                }
            },
            passkeys: {
                deleteAllCredentials: async user => {
                    state.cleared.push(user);
                    return 2;
                }
            },
            logger: { debug() {}, info() {} }
        }
    };
}

test('a rotated prepared password removes the passkeys and ends sessions', async () => {
    const { state, deps } = makeDeps({ user: 'admin', password: '$pbkdf2-old', passwordVersion: 1000 });
    const result = await importPreparedPassword('$pbkdf2-new', deps);
    assert.deepEqual(result, { imported: true, clearedPasskeys: 2 });
    assert.equal(state.authData.password, '$pbkdf2-new');
    assert.ok(state.authData.passwordVersion > 1000);
    assert.deepEqual(state.cleared, ['admin']);
});

test('the same prepared password on a later boot changes nothing', async () => {
    const { state, deps } = makeDeps({ user: 'admin', password: '$pbkdf2-same', passwordVersion: 1000 });
    assert.deepEqual(await importPreparedPassword('$pbkdf2-same', deps), { imported: false, clearedPasskeys: 0 });
    assert.equal(state.authData.passwordVersion, 1000);
    assert.deepEqual(state.cleared, []);
});

test('a first import on an instance without a password sets the admin user', async () => {
    const { state, deps } = makeDeps(undefined);
    await importPreparedPassword('$pbkdf2-new', deps);
    assert.equal(state.authData.user, 'admin');
    assert.deepEqual(state.cleared, ['admin']);
});
