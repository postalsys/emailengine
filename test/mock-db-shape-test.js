'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');

const { installDbMock } = require('./helpers/mock-db');

// lib/db opens Redis and BullMQ connections on require, so its export names are read from the
// source instead. Every export there is a `module.exports.<name> =` assignment.
function dbExportNames() {
    const source = fs.readFileSync(path.join(__dirname, '..', 'lib', 'db.js'), 'utf-8');
    assert.ok(!/^\s*module\.exports\s*=/m.test(source), 'lib/db.js replaced module.exports wholesale; update this parser');
    return [...source.matchAll(/^module\.exports\.([A-Za-z_$][\w$]*)\s*=/gm)].map(match => match[1]).sort();
}

test('the mock-db helper exports the same names as lib/db', () => {
    const dbPath = require.resolve('../lib/db');
    const getSecretPath = require.resolve('../lib/get-secret');
    installDbMock();
    try {
        const mockNames = Object.keys(require.cache[dbPath].exports).sort();
        const realNames = dbExportNames();

        assert.ok(realNames.includes('redis') && realNames.includes('QUEUES_BY_NAME'), 'the source parser found the known exports');
        assert.deepStrictEqual(mockNames, realNames);
    } finally {
        delete require.cache[dbPath];
        delete require.cache[getSecretPath];
    }
});
