'use strict';

// Tripwire: every key read with `settings.get('<key>')` is either declared in settingsSchema, so an
// operator can set it, or listed below as internal state the instance writes itself.
//
// Nothing else connects the two. `settings.get()` reads a Redis hash field and answers the default for
// a key nobody ever wrote, so a read of a key that no schema declares is silently a constant: the
// export retention window and the per-message size cap were read that way for as long as they had
// existed, always falling back to their defaults because neither POST /v1/settings nor the admin UI
// could write them.
//
// Pure filesystem read plus the schema module - no Redis, no server.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { settingsSchema } = require('../lib/schemas');

const ROOT = pathlib.join(__dirname, '..');

// Fields the instance stores in the settings hash for itself. None of them is an operator knob, which
// is why none is in settingsSchema: POST /v1/settings validates against that object, so a key here is
// one a client cannot write. Each entry names what writes it.
const INTERNAL_KEYS = new Map([
    ['authData', 'the admin password hash and its version (lib/ui-routes/auth-routes.js)'],
    ['cookiePassword', 'the admin session cookie key, generated at first boot (server.js)'],
    ['disableTokens', 'mirrors EENGINE_REQUIRE_API_AUTH, written at boot (server.js)'],
    ['enableOAuthTokensApi', 'mirrors its environment flag, written at boot (server.js)'],
    ['openAiModels', 'the model list fetched from the configured AI endpoint (lib/ui-routes/admin-config-routes.js)'],
    ['preparedSettingsKeys', 'the keys EENGINE_SETTINGS owns, so the forms can flag them (server.js)'],
    ['sentryAutoEnabled', 'marker recording that error reporting was switched on by default (lib/settings.js)'],
    ['serviceId', 'the instance identifier, generated at first boot (server.js)'],
    ['subexp', 'the subscription expiry carried by the license check (server.js)'],
    ['totpEnabled', 'whether TOTP is set up (lib/ui-routes/auth-routes.js)'],
    ['totpSeed', 'the TOTP secret (lib/ui-routes/auth-routes.js)'],
    ['webhookErrorFlag', 'the last webhook delivery failure, for the dashboard notice (workers/webhooks.js)']
]);

// Only string-literal reads are collected. A computed key cannot be checked here, and there are none.
// The scan is textual, so a comment quoting a read counts as one - write about a key by name rather
// than by spelling the call out.
const READ_PATTERN = /settings\.get\('([a-zA-Z0-9_]+)'/g;

function sourceFiles() {
    const files = [pathlib.join(ROOT, 'server.js')];
    const walk = dir => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = pathlib.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(full);
            } else if (entry.name.endsWith('.js')) {
                files.push(full);
            }
        }
    };
    for (const dir of ['lib', 'workers', 'bin']) {
        walk(pathlib.join(ROOT, dir));
    }
    return files;
}

test('every settings key that is read is either settable or declared internal', () => {
    const schemaKeys = new Set(Object.keys(settingsSchema));
    const unknown = new Map();

    for (const file of sourceFiles()) {
        const content = fs.readFileSync(file, 'utf-8');
        for (const match of content.matchAll(READ_PATTERN)) {
            const key = match[1];
            if (schemaKeys.has(key) || INTERNAL_KEYS.has(key)) {
                continue;
            }
            if (!unknown.has(key)) {
                unknown.set(key, pathlib.relative(ROOT, file));
            }
        }
    }

    assert.deepEqual(
        [...unknown.entries()],
        [],
        `These settings keys are read but no schema declares them, so the read always answers the default. ` +
            `Add the key to settingsSchema in lib/schemas.js to make it settable, or to INTERNAL_KEYS in this test ` +
            `if the instance writes it itself:\n${[...unknown].map(([key, file]) => `  ${key} (${file})`).join('\n')}`
    );
});

test('no internal key is also a settable one', () => {
    // A key in both lists means the allowlist is hiding a real schema entry, and the next person to
    // remove that entry would get no failure
    const schemaKeys = new Set(Object.keys(settingsSchema));
    assert.deepEqual(
        [...INTERNAL_KEYS.keys()].filter(key => schemaKeys.has(key)),
        []
    );
});

test('every declared internal key is still read somewhere', () => {
    // Otherwise the allowlist outlives the code it was written for and starts excusing a new key that
    // happens to share the name
    const read = new Set();
    for (const file of sourceFiles()) {
        for (const match of fs.readFileSync(file, 'utf-8').matchAll(READ_PATTERN)) {
            read.add(match[1]);
        }
    }
    assert.deepEqual(
        [...INTERNAL_KEYS.keys()].filter(key => !read.has(key)),
        []
    );
});
