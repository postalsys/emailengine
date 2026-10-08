'use strict';

// EENGINE_IGNORE_ADDRESS_LENGTH, which lets the sender and recipient fields of a submitted message
// skip joi's RFC 5321 size limits. lib/schemas.js reads the variable once at load, so each case runs
// in a child process with its own environment - the same `execFileSync(process.execPath, ...)` shape
// test/read-env-value-test.js uses.

const test = require('node:test');
const assert = require('node:assert').strict;
const pathlib = require('path');
const { execFileSync } = require('child_process');

const ROOT = pathlib.join(__dirname, '..');

// Printed after the schemas have loaded, so the log lines written before it can be told from the answer
const MARKER = '__ADDRESS_LENGTH__';

// Shaped like a ClickUp per-task address (made-up ids): 65 octets in the local part, one over the RFC 5321 limit
const LONG_LOCAL_PART = 'A.t.123456789012.u-123456789.00000000-0000-4000-8000-000000000000@tasks.clickup.com';
// Syntactically invalid regardless of length
const MALFORMED = 'name.@example.com';

const SCRIPT = `
    const { addressSchema, envelopeAddressSchema } = require('./lib/schemas');
    const addresses = JSON.parse(process.env.PROBE_ADDRESSES);
    const result = {};
    for (const address of addresses) {
        result[address] = {
            address: !addressSchema.validate({ address }).error,
            envelope: !envelopeAddressSchema.validate(address).error
        };
    }
    process.stdout.write('\\n${MARKER}' + JSON.stringify(result) + '\\n');
    // Requiring lib/schemas opens Redis handles that would keep this process alive
    process.exit(0);
`;

function probe(env) {
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
                PROBE_ADDRESSES: JSON.stringify([LONG_LOCAL_PART, MALFORMED])
            },
            env
        )
    });

    const marked = stdout.split('\n').find(line => line.startsWith(MARKER));
    assert.ok(marked, `the probe printed no answer:\n${stdout}`);
    return JSON.parse(marked.slice(MARKER.length));
}

test('address length limits', async t => {
    await t.test('are enforced by default', () => {
        const result = probe({});
        assert.deepEqual(result[LONG_LOCAL_PART], { address: false, envelope: false });
        assert.deepEqual(result[MALFORMED], { address: false, envelope: false });
    });

    await t.test('are skipped when EENGINE_IGNORE_ADDRESS_LENGTH is set', () => {
        const result = probe({ EENGINE_IGNORE_ADDRESS_LENGTH: 'true' });
        assert.deepEqual(result[LONG_LOCAL_PART], { address: true, envelope: true });
        // Only the length check is relaxed, not the address syntax
        assert.deepEqual(result[MALFORMED], { address: false, envelope: false });
    });
});
