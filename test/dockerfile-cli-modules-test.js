'use strict';

// The Dockerfile copies an explicit allowlist of root-level files rather than `COPY . .`, so a
// root-level module that bin/emailengine.js dispatches to is easy to forget. When that happens the
// server still boots (CMD only runs server.js) and the image builds green, but the CLI subcommand
// fails with MODULE_NOT_FOUND inside the container - the documented `docker exec ... node
// bin/emailengine.js <command>` path. Both `scan` and `encrypt` shipped broken this way.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const Path = require('path');

const repoRoot = Path.join(__dirname, '..');
const cliSource = fs.readFileSync(Path.join(repoRoot, 'bin', 'emailengine.js'), 'utf8');
const dockerfile = fs.readFileSync(Path.join(repoRoot, 'Dockerfile'), 'utf8');

// Root-level requires only: `require('../name')` with no further path separator, in any quote style
// (single, double, backtick). `../lib/x` and bare package names are out of scope - lib/ is copied
// wholesale and packages come from npm ci.
function rootLevelRequires(source) {
    let names = new Set();
    for (let match of source.matchAll(/require\(\s*['"`]\.\.\/([^'"`/]+)['"`]\s*\)/g)) {
        names.add(match[1]);
    }
    return [...names].sort();
}

// require.resolve IS Node's resolution, so this cannot drift from what the CLI does at runtime the
// way a hand-rolled extension search would. It only resolves, never executes, so `../server` stays
// inert.
function resolveRootModule(name) {
    try {
        return Path.relative(repoRoot, require.resolve(Path.join(repoRoot, name)));
    } catch (err) {
        return null;
    }
}

// Source paths of every COPY in the Dockerfile. Handles the real Dockerfile grammar rather than a
// single (source) capture: any number of `--flag[=value]` options and multiple sources (the last
// token is the destination). A too-narrow regex here caused false failures on legitimate refactors
// (a second flag, or a consolidated multi-source COPY).
function copiedSources(dockerfileText) {
    let sources = new Set();
    for (let match of dockerfileText.matchAll(/^COPY\s+(.+)$/gm)) {
        // Drop --flag tokens, then every remaining token except the last (the destination) is a source.
        let tokens = match[1]
            .trim()
            .split(/\s+/)
            .filter(token => !token.startsWith('--'));
        for (let source of tokens.slice(0, -1)) {
            sources.add(source);
        }
    }
    return sources;
}

const copiedFiles = copiedSources(dockerfile);

test('Dockerfile copies every root-level module the CLI requires', async t => {
    const required = rootLevelRequires(cliSource);

    await t.test('the CLI actually has root-level requires to check', () => {
        // Guards the regex itself: if a refactor changes the require style, this test must not
        // silently start passing by finding nothing.
        assert.ok(required.length > 0, 'expected bin/emailengine.js to require at least one root-level module');
    });

    for (let name of required) {
        await t.test(`\`${name}\` resolves in the repo and is copied into the image`, () => {
            let fileName = resolveRootModule(name);
            assert.ok(fileName, `bin/emailengine.js requires '../${name}' but no such file exists at the repo root`);
            assert.ok(
                copiedFiles.has(fileName),
                `bin/emailengine.js requires '../${name}', but the Dockerfile never copies ${fileName} - ` +
                    `the command will fail with MODULE_NOT_FOUND inside the container. Add "COPY ${fileName} ${fileName}".`
            );
        });
    }
});
