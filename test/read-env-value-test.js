'use strict';

// What readEnvValue() resolves a `<KEY>_FILE` variable to, and when it says the value has changed.
//
// The helper writes the resolved value back into process.env and logs through pino, so each case runs
// in its own child process: an in-process test would see the cached value of whichever case ran first,
// and could not read the log line at all. The same `execFileSync(process.execPath, ...)` shape
// test/acme-config-guardrail-test.js uses - the Node binary already running, not a CLI tool.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const os = require('os');
const pathlib = require('path');
const { execFileSync } = require('child_process');

const ROOT = pathlib.join(__dirname, '..');

// Printed after the helper has run, so the log lines pino wrote before it can be told from the answer
const MARKER = '__READ_ENV_VALUE__';

const SCRIPT = `
    const { readEnvValue } = require('./lib/read-env-value');
    const value = readEnvValue(process.env.PROBE_KEY);
    process.stdout.write('\\n${MARKER}' + JSON.stringify({ value }) + '\\n');
`;

function resolve(key, env) {
    const stdout = execFileSync(process.execPath, ['-e', SCRIPT], {
        cwd: ROOT,
        encoding: 'utf-8',
        env: Object.assign(
            {
                PATH: process.env.PATH,
                HOME: process.env.HOME,
                NODE_ENV: 'test',
                // dotenv would otherwise load the developer's own .env over the case being set up
                EE_ENV_LOADED: 'true',
                PROBE_KEY: key
            },
            env
        )
    });

    const marked = stdout.split('\n').find(line => line.startsWith(MARKER));
    assert.ok(marked, `the probe printed no answer:\n${stdout}`);

    return {
        value: JSON.parse(marked.slice(MARKER.length)).value,
        // Every other line is a pino record; only the warning this helper emits is of interest
        warnings: stdout
            .split('\n')
            .filter(line => line.startsWith('{'))
            .map(line => JSON.parse(line))
            .filter(entry => entry.level >= 40)
    };
}

test('readEnvValue resolves a file-backed variable', async t => {
    const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-env-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    let fileIndex = 0;
    const fileWith = contents => {
        const file = pathlib.join(dir, `value-${fileIndex++}.txt`);
        fs.writeFileSync(file, contents);
        return file;
    };

    await t.test('a value written with a trailing newline resolves without it', () => {
        const { value, warnings } = resolve('EENGINE_SECRET', { EENGINE_SECRET_FILE: fileWith('s3cret\n') });
        assert.equal(value, 's3cret');
        assert.deepEqual(warnings, [], 'the shape `echo value > file` produces is not a change');
    });

    await t.test('CRLF line endings resolve to the same value', () => {
        // A file written on Windows and mounted into the container must not produce a different
        // secret, which is the case most likely to warn when it should not
        const { value, warnings } = resolve('EENGINE_SECRET', { EENGINE_SECRET_FILE: fileWith('s3cret\r\n') });
        assert.equal(value, 's3cret');
        assert.deepEqual(warnings, []);
    });

    await t.test('a variable set directly is used verbatim', () => {
        // The file form is the only one that trims. A value given in the environment is the operator
        // saying exactly what it is, and it is also the way back from the warning below.
        assert.equal(resolve('EENGINE_SECRET', { EENGINE_SECRET: '  s3cret  ' }).value, '  s3cret  ');
    });

    await t.test('a secret whose resolved value changed says so', () => {
        // lib/db.js and lib/get-secret.js used to strip one trailing newline and nothing else. For
        // EENGINE_SECRET a different value means every stored credential stops decrypting, so the
        // difference is reported rather than left to be discovered by the accounts failing.
        const { value, warnings } = resolve('EENGINE_SECRET', { EENGINE_SECRET_FILE: fileWith(' s3cret \n\n') });

        assert.equal(value, 's3cret');
        assert.equal(warnings.length, 1, 'exactly one warning');
        assert.equal(warnings[0].key, 'EENGINE_SECRET');
        assert.match(warnings[0].msg, /whitespace/);
        // The value is what the warning exists to protect; it must not be in the line that reports it
        assert.ok(!JSON.stringify(warnings[0]).includes('s3cret'), 'the warning does not carry the value');
    });

    await t.test('a variable that never had the old behavior stays quiet', () => {
        // Only the two modules that carried private copies resolved their variables the old way, so
        // only their keys can have changed. Warning for the rest would be noise on every boot.
        const { value, warnings } = resolve('EENGINE_MAX_SIZE', { EENGINE_MAX_SIZE_FILE: fileWith(' 5MB \n\n') });
        assert.equal(value, '5MB');
        assert.deepEqual(warnings, []);
    });
});
