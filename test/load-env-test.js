'use strict';

// lib/load-env.js replaced the dotenv package. Each case runs in a child process with its own
// working directory, since process.loadEnvFile() writes into the process environment.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const os = require('node:os');
const pathlib = require('node:path');
const { execFileSync } = require('node:child_process');

const LOAD_ENV = pathlib.join(__dirname, '..', 'lib', 'load-env.js');

// Runs `script` with lib/load-env.js as `loadEnv`, in a directory holding `files`, and returns
// what the script printed as JSON
function run(script, { files = {}, env = {} } = {}) {
    const dir = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'load-env-'));
    try {
        for (const [name, content] of Object.entries(files)) {
            if (content === null) {
                fs.mkdirSync(pathlib.join(dir, name));
            } else {
                fs.writeFileSync(pathlib.join(dir, name), content);
            }
        }
        const output = execFileSync(process.execPath, ['-e', `const loadEnv = require(${JSON.stringify(LOAD_ENV)}); ${script}`], {
            cwd: dir,
            encoding: 'utf-8',
            env: { PATH: process.env.PATH, ...env },
            stdio: ['ignore', 'pipe', 'pipe']
        });
        return JSON.parse(output);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

// Values dotenv produced for the same file, recorded before it was removed
const DOTENV_FILE = [
    'PLAIN=value',
    'SPACED = spaced value ',
    'export EXPORTED=yes',
    'DQ="double quoted"',
    "SQ='single quoted'",
    'BT=`backtick quoted`',
    'ESC="line1\\nline2"',
    "RAWESC='line1\\nline2'",
    'MULTI="first',
    'second"',
    'HASH=value # comment',
    'HASHQ="value # not comment"',
    'EMPTY=',
    'URL=redis://user:pa$$@127.0.0.1:6379/8',
    'EQ=a=b=c',
    '# comment line',
    '',
    'JSON={"a":1}',
    'EENGINE_SETTINGS=\'{"x":"y"}\''
].join('\n');

const DOTENV_VALUES = {
    PLAIN: 'value',
    SPACED: 'spaced value',
    EXPORTED: 'yes',
    DQ: 'double quoted',
    SQ: 'single quoted',
    BT: 'backtick quoted',
    ESC: 'line1\nline2',
    RAWESC: 'line1\\nline2',
    MULTI: 'first\nsecond',
    HASH: 'value',
    HASHQ: 'value # not comment',
    EMPTY: '',
    URL: 'redis://user:pa$$@127.0.0.1:6379/8',
    EQ: 'a=b=c',
    JSON: '{"a":1}',
    EENGINE_SETTINGS: '{"x":"y"}'
};

test('parses a .env file the way dotenv did', () => {
    const keys = JSON.stringify(Object.keys(DOTENV_VALUES));
    const result = run(`loadEnv.loadEnvFile(); console.log(JSON.stringify(Object.fromEntries(${keys}.map(k => [k, process.env[k]]))))`, {
        files: { '.env': DOTENV_FILE }
    });
    assert.deepEqual(result, DOTENV_VALUES);
});

test('never overwrites a variable that is already set', () => {
    const result = run('console.log(JSON.stringify([loadEnv.loadEnvFile(), process.env.PLAIN, process.env.OTHER]))', {
        files: { '.env': 'PLAIN=from-file\nOTHER=from-file' },
        env: { PLAIN: 'from-environment' }
    });
    assert.deepEqual(result, [true, 'from-environment', 'from-file']);
});

test('a missing file is silent', () => {
    const result = run('console.log(JSON.stringify(loadEnv.loadEnvFile()))');
    assert.equal(result, false);
});

test('a .env that cannot be read is reported and does not stop the process', () => {
    // a directory named .env: reading it fails with EISDIR
    const result = run('console.log(JSON.stringify(loadEnv.loadEnvFile()))', { files: { '.env': null } });
    assert.equal(result, false);
});

test('loadEnvOnce loads the file once per process', () => {
    const result = run(
        `loadEnv.loadEnvOnce(); const first = process.env.VALUE; require('fs').writeFileSync('.env', 'VALUE=second\\nLATER=yes'); delete process.env.VALUE; loadEnv.loadEnvOnce(); console.log(JSON.stringify([first, process.env.VALUE, process.env.LATER, process.env.EE_ENV_LOADED]))`,
        { files: { '.env': 'VALUE=first' } }
    );
    // unset variables come back as null through JSON
    assert.deepEqual(result, ['first', null, null, 'true']);
});

test('does nothing on a Node.js release without process.loadEnvFile', () => {
    const result = run('process.loadEnvFile = undefined; console.log(JSON.stringify([loadEnv.loadEnvFile(), process.env.VALUE || null]))', {
        files: { '.env': 'VALUE=x' }
    });
    assert.deepEqual(result, [false, null]);
});
