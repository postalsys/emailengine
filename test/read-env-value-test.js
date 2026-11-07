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

// lib/consts.js reads its variables through readEnvValue() while it is itself still loading, and the
// helper reports through lib/logger.js. The logger used to require lib/consts.js as well, a cycle the
// helper got around by deferring every report by a tick; it takes its constants from the leaf
// lib/logger-consts.js now. These cases load consts first, the way every worker does, and check both
// the value and that the report arrives.
const CONSTS_SCRIPT = `
    const consts = require('./lib/consts');
    process.stdout.write('\\n${MARKER}' + JSON.stringify({ value: consts[process.env.PROBE_CONST] }) + '\\n');
`;

function resolveConst(name, env) {
    const stdout = execFileSync(process.execPath, ['-e', CONSTS_SCRIPT], {
        cwd: ROOT,
        encoding: 'utf-8',
        // both streams captured, so a probe that fails to load reports why on the thrown error
        stdio: ['ignore', 'pipe', 'pipe'],
        env: Object.assign(
            {
                PATH: process.env.PATH,
                HOME: process.env.HOME,
                NODE_ENV: 'test',
                EE_ENV_LOADED: 'true',
                EENGINE_LOG_LEVEL: 'trace',
                PROBE_CONST: name
            },
            env
        )
    });
    const marked = stdout.split('\n').find(line => line.startsWith(MARKER));
    assert.ok(marked, `the probe printed no answer:\n${stdout}`);
    return {
        value: JSON.parse(marked.slice(MARKER.length)).value,
        records: stdout
            .split('\n')
            .filter(line => line.startsWith('{'))
            .map(line => JSON.parse(line))
    };
}

test('lib/consts.js variables honor the file form', async t => {
    const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-env-consts-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    await t.test('EENGINE_REDIS_PREFIX_FILE sets the key prefix', () => {
        const file = pathlib.join(dir, 'prefix.txt');
        fs.writeFileSync(file, 'tenant-a\n');
        const { value, records } = resolveConst('REDIS_PREFIX', { EENGINE_REDIS_PREFIX_FILE: file });
        assert.equal(value, 'tenant-a:');
        assert.ok(
            records.some(entry => entry.msg === 'Loaded environment value from file' && entry.key === 'EENGINE_REDIS_PREFIX'),
            'the read is reported once the logger can be loaded'
        );
    });

    await t.test('the variable itself still wins over the file', () => {
        const file = pathlib.join(dir, 'prefix-ignored.txt');
        fs.writeFileSync(file, 'from-file');
        const { value } = resolveConst('REDIS_PREFIX', { EENGINE_REDIS_PREFIX: 'direct', EENGINE_REDIS_PREFIX_FILE: file });
        assert.equal(value, 'direct:');
    });

    await t.test('an unset prefix stays empty', () => {
        const { value } = resolveConst('REDIS_PREFIX', {});
        assert.equal(value, '');
    });

    await t.test('an unreadable file stops the process instead of leaving the default', () => {
        // It used to resolve to '' and so to the default: a missing admin password hash file
        // booted with /admin open. A file the operator named and that can not be read now fails
        // the load, naming the variable and the file.
        const missing = pathlib.join(dir, 'missing.txt');
        assert.throws(
            () => resolveConst('URL_FETCH_TIMEOUT', { EENGINE_FETCH_TIMEOUT_FILE: missing }),
            err => {
                // the logger's uncaughtException handler writes the report to stdout
                const output = `${err.stdout}${err.stderr}`;
                assert.notEqual(err.status, 0);
                assert.match(output, /Can not read EENGINE_FETCH_TIMEOUT_FILE/);
                assert.ok(output.includes(missing));
                return true;
            }
        );
    });
});

test('the logger does not load lib/consts.js, so reading an environment value can log at once', () => {
    // A cycle here is what made the helper defer its reports: pino would otherwise be built from a
    // half-initialized consts object
    const loaded = execFileSync(
        process.execPath,
        ['-e', "require('./lib/logger'); process.stdout.write(JSON.stringify(Object.keys(require.cache).filter(k => /lib[\\/]consts\\.js$/.test(k))))"],
        { cwd: ROOT, encoding: 'utf-8', env: Object.assign({}, process.env, { EE_ENV_LOADED: 'true' }) }
    );
    assert.deepEqual(JSON.parse(loaded), []);
});

// An unreadable file used to resolve to '', which every reader takes for "not configured": a
// missing EENGINE_PREPARED_PASSWORD_FILE booted the instance with /admin open. It now throws, and
// server.js resolves every file variable before anything else so the boot stops by name.
test('an unreadable file fails closed', async t => {
    const { readEnvValue, resolveEnvFiles } = require('../lib/read-env-value');
    const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-env-'));
    const missing = pathlib.join(dir, 'admin-password-hash');
    const keys = ['EENGINE_PREPARED_PASSWORD', 'EENGINE_ADMIN_ACCESS_ADDRESSES'];
    const saved = {};
    for (const key of keys) {
        for (const name of [key, `${key}_FILE`]) {
            saved[name] = process.env[name];
            delete process.env[name];
        }
    }
    t.after(() => {
        for (const [name, value] of Object.entries(saved)) {
            if (value === undefined) {
                delete process.env[name];
            } else {
                process.env[name] = value;
            }
        }
        fs.rmSync(dir, { recursive: true, force: true });
    });

    await t.test('readEnvValue throws instead of resolving to an empty value', () => {
        process.env.EENGINE_PREPARED_PASSWORD_FILE = missing;
        assert.throws(
            () => readEnvValue('EENGINE_PREPARED_PASSWORD'),
            err => err.code === 'EnvFileUnreadable' && err.key === 'EENGINE_PREPARED_PASSWORD' && err.message.includes(missing)
        );
        // nothing is cached, so every later read refuses too
        assert.equal('EENGINE_PREPARED_PASSWORD' in process.env, false);
        assert.throws(() => readEnvValue('EENGINE_PREPARED_PASSWORD'), { code: 'EnvFileUnreadable' });
        delete process.env.EENGINE_PREPARED_PASSWORD_FILE;
    });

    await t.test('resolveEnvFiles reads every file variable up front', () => {
        const file = pathlib.join(dir, 'perimeter');
        fs.writeFileSync(file, '10.0.0.0/8\n');
        process.env.EENGINE_ADMIN_ACCESS_ADDRESSES_FILE = file;
        resolveEnvFiles();
        assert.equal(process.env.EENGINE_ADMIN_ACCESS_ADDRESSES, '10.0.0.0/8');

        process.env.EENGINE_PREPARED_PASSWORD_FILE = missing;
        assert.throws(() => resolveEnvFiles(), { code: 'EnvFileUnreadable' });
        delete process.env.EENGINE_PREPARED_PASSWORD_FILE;
    });
});
