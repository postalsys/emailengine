'use strict';

// Writes to an account's `iad:` hash from the sync clients and the main thread's event counters
// must go through hSetExists / hIncrbyExists. A plain HSET or HINCRBY that lands after the account
// was deleted (a history run, a send or an event still in flight) recreates the hash with a few
// stray fields, and an account later created with the same ID merges into it and inherits them,
// a stale googleHistoryId among them.
//
// Writes made while setting an account up or under its own lock in lib/account.js are not covered:
// those know the account exists.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function sources() {
    const dir = path.join(ROOT, 'lib', 'email-client');
    const files = [path.join(ROOT, 'server.js')];
    const walk = current => {
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const full = path.join(current, entry.name);
            if (entry.isDirectory()) {
                walk(full);
            } else if (entry.name.endsWith('.js')) {
                files.push(full);
            }
        }
    };
    walk(dir);
    return files;
}

// HSETNX in a client's init() only seeds a value on an account that was just loaded
const PLAIN_WRITE = /\.(hset|hincrby|hmset)\(\s*(this\.getAccountKey\(\)|accountKey\b|`\$\{REDIS_PREFIX\}iad:)/g;

test('account hash writes use the exists-guarded helpers', () => {
    const offenders = [];
    for (const file of sources()) {
        const source = fs.readFileSync(file, 'utf-8');
        for (const match of source.matchAll(PLAIN_WRITE)) {
            const line = source.slice(0, match.index).split('\n').length;
            offenders.push(`${path.relative(ROOT, file)}:${line} ${match[0]}`);
        }
    }
    assert.deepStrictEqual(offenders, [], 'use hSetExists/hIncrbyExists for writes to an account hash');
});
