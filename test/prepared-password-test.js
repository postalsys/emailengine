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
            logger: { debug() {}, info() {}, error() {} }
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

// Every way of replacing the admin password goes through setAdminPassword(), so none of them can
// forget the passkeys: the prepared-password import once did
test('setAdminPassword() stores the hash, ends sessions and removes passkeys, even when the removal fails', async () => {
    const { setAdminPassword } = require('../lib/admin-password');
    const errors = [];
    const { state, deps } = makeDeps({ user: 'operator', password: '$pbkdf2-old', passwordVersion: 1000 });
    deps.logger.error = entry => errors.push(entry.msg);

    const { authData, clearedPasskeys } = await setAdminPassword('$pbkdf2-new', deps);
    assert.equal(clearedPasskeys, 2);
    assert.equal(authData.password, '$pbkdf2-new');
    assert.ok(authData.passwordVersion > 1000);
    assert.deepEqual(state.cleared, ['operator']);

    deps.passkeys.deleteAllCredentials = async () => {
        throw new Error('redis down');
    };
    const failed = await setAdminPassword('$pbkdf2-newer', deps);
    assert.equal(failed.clearedPasskeys, 0);
    assert.equal(state.authData.password, '$pbkdf2-newer', 'the password is replaced either way');
    assert.deepEqual(errors, ['Failed to clear passkeys after password change']);
});

test('nothing but setAdminPassword() replaces the admin password', () => {
    const fs = require('fs');
    const pathlib = require('path');
    const root = pathlib.join(__dirname, '..');
    // the sign-in rehash stores the same password at stronger hash settings, so sessions and
    // passkeys rightly stay
    const allowed = new Set(['lib/admin-password.js', 'lib/ui-routes/sign-in-helpers.js']);
    const files = [];
    const walk = dir => {
        for (const entry of fs.readdirSync(pathlib.join(root, dir), { withFileTypes: true })) {
            const rel = `${dir}/${entry.name}`;
            if (entry.isDirectory()) {
                walk(rel);
            } else if (entry.name.endsWith('.js')) {
                files.push(rel);
            }
        }
    };
    ['lib', 'bin', 'workers'].forEach(walk);
    files.push('server.js');
    const writers = files.filter(file => /authData\.password\s*=[^=]/.test(fs.readFileSync(pathlib.join(root, file), 'utf-8')));
    assert.deepEqual(
        writers.filter(file => !allowed.has(file)),
        []
    );
});
