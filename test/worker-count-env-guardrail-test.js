'use strict';

// Tripwire: every environment variable the Workers page names as a worker count is actually read.
//
// server.js carries two lists that have to agree and nothing connected them: the overrides at the top
// that resolve each count from its variable, and THREAD_CONFIG_VALUES, whose key is what
// /admin/internals prints beside the thread. EENGINE_WORKERS_EXPORT sat in the second list and not the
// first for as long as the export worker had existed, so an operator who set it saw no effect and the
// page told them the name was right.
//
// server.js cannot be required from a test - it boots the whole instance - so the lists are read as
// text. Both are plain literals, which is what makes that sound.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const SERVER = fs.readFileSync(pathlib.join(__dirname, '..', 'server.js'), 'utf-8');

test('every worker count the Workers page names is read from its environment variable', () => {
    const table = SERVER.match(/const THREAD_CONFIG_VALUES = \{([\s\S]*?)\n\};/);
    assert.ok(table, 'THREAD_CONFIG_VALUES was not found in server.js');

    const named = [...table[1].matchAll(/key: '([A-Z0-9_]+)'/g)].map(match => match[1]);
    assert.ok(named.length >= 5, `expected a key per worker type, found ${named.length}`);

    const unread = named.filter(key => !SERVER.includes(`readEnvValue('${key}')`));
    assert.deepEqual(
        unread,
        [],
        `These variables are printed on /admin/internals as the setting behind a worker count, but server.js ` +
            `never reads them, so setting one has no effect:\n${unread.join('\n')}`
    );
});

test('the Workers page documents every variable the table names', () => {
    const page = fs.readFileSync(pathlib.join(__dirname, '..', 'views', 'internals', 'index.hbs'), 'utf-8');
    const table = SERVER.match(/const THREAD_CONFIG_VALUES = \{([\s\S]*?)\n\};/);
    const named = [...table[1].matchAll(/key: '([A-Z0-9_]+)'/g)].map(match => match[1]);

    const undocumented = named.filter(key => !page.includes(key));
    assert.deepEqual(undocumented, [], `The "About workers" section leaves these out:\n${undocumented.join('\n')}`);
});
