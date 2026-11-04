'use strict';

// What the runtime stage of the published image promises an orchestrator: a health check it can
// run without docker-compose, the port it listens on, and an application tree the process cannot
// rewrite. Pure filesystem read.

const test = require('node:test');
const assert = require('node:assert').strict;

const { readDockerfile, copiedSources } = require('./helpers/dockerfile');

const dockerfile = readDockerfile();
// Everything after the last FROM is the image that ships
const runtimeStage = dockerfile.slice(dockerfile.lastIndexOf('\nFROM '));

test('the runtime image declares a health check that follows the API listener', () => {
    const healthcheck = runtimeStage.match(/^HEALTHCHECK\b[\s\S]*?CMD\s+(.+)$/m);
    assert.ok(healthcheck, 'the runtime stage has a HEALTHCHECK instruction');
    // A fixed http URL failed on every instance serving the API over HTTPS; bin/healthcheck.js
    // resolves the port, bind address and TLS switch the way the API worker does
    assert.match(healthcheck[1], /bin\/healthcheck\.js/);
    assert.doesNotMatch(healthcheck[1], /wget|http:\/\//, 'no hard-coded protocol');
});

test('the health check script ships in the image', () => {
    assert.ok(copiedSources(dockerfile).has('bin'), 'bin/ is copied, so bin/healthcheck.js is there to run');
});

test('the runtime image exposes the default API port', () => {
    assert.match(runtimeStage, /^EXPOSE\s+3000\b/m);
});

test('the application tree is not owned by the runtime user', () => {
    const copies = [...runtimeStage.matchAll(/^COPY\s+(.+)$/gm)].map(match => match[1]);
    const appCopy = copies.find(line => /\s\/emailengine\s*$/.test(line));
    assert.ok(appCopy, 'the runtime stage copies the application into /emailengine');
    assert.doesNotMatch(appCopy, /--chown/, 'a tree the process owns is a tree it can rewrite');
    assert.match(runtimeStage, /^USER\s+emailengineuser\b/m, 'the process still does not run as root');
});
