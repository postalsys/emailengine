'use strict';

// lib/redis-keys.js names the Redis keys that more than one module builds. A key spelled by hand
// somewhere else and spelled slightly differently reads an empty key instead of failing, so this
// guardrail fails on a hand-built copy of a key the module owns.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');

const { accountDataKey } = require('../lib/redis-keys');
const { REDIS_PREFIX } = require('../lib/consts');
const { listFiles } = require('./helpers/list-files');

const root = path.join(__dirname, '..');
const OWNER = path.join(root, 'lib', 'redis-keys.js');

// A key written as a template literal or a string concatenation starting from the prefix
const HAND_BUILT = [{ key: 'iad:', pattern: /REDIS_PREFIX\s*\}?\s*\+?\s*['"`]?iad:/ }];

test('Redis key names', async t => {
    await t.test('the account data key', () => {
        assert.equal(accountDataKey('acc1'), `${REDIS_PREFIX}iad:acc1`);
    });

    await t.test('no module builds an owned key by hand', () => {
        const sources = [path.join(root, 'server.js'), ...listFiles(path.join(root, 'lib'), '.js'), ...listFiles(path.join(root, 'workers'), '.js')];
        const offenders = [];
        for (const file of sources) {
            if (file === OWNER || file.includes(`${path.sep}imap-core${path.sep}`)) {
                continue;
            }
            const lines = fs.readFileSync(file, 'utf8').split('\n');
            lines.forEach((line, index) => {
                for (const { key, pattern } of HAND_BUILT) {
                    if (pattern.test(line)) {
                        offenders.push(`${path.relative(root, file)}:${index + 1} builds "${key}" by hand`);
                    }
                }
            });
        }
        assert.deepEqual(offenders, [], `use lib/redis-keys.js instead:\n${offenders.join('\n')}`);
    });

    await t.test('the guardrail pattern recognises the forms a key is built in', () => {
        const { pattern } = HAND_BUILT[0];
        assert.ok(pattern.test('redis.hget(`${REDIS_PREFIX}iad:${account}`, "x")'));
        assert.ok(pattern.test("redis.hget(REDIS_PREFIX + 'iad:' + account)"));
        assert.ok(!pattern.test('redis.hget(accountDataKey(account))'));
    });
});
