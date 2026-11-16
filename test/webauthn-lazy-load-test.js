'use strict';

// lib/ui-routes/auth-routes.js loads @simplewebauthn/server on the first passkey request, not with
// the admin UI: see the comment there. Checked in a child process, so this file's own module cache
// does not count.

const test = require('node:test');
const assert = require('node:assert').strict;
const pathlib = require('node:path');
const { execFileSync } = require('node:child_process');

test('loading the admin auth routes does not load the passkey library', () => {
    const output = execFileSync(
        process.execPath,
        [
            '-e',
            "require('./lib/ui-routes/auth-routes'); console.log(JSON.stringify(Object.keys(require.cache).filter(f => /simplewebauthn|reflect-metadata|tsyringe/.test(f)).length)); process.exit(0)"
        ],
        { cwd: pathlib.join(__dirname, '..'), encoding: 'utf-8', env: { ...process.env, NODE_ENV: 'test' } }
    ).trim();
    assert.equal(output.split('\n').pop(), '0');
});
