'use strict';

// The Docker image and the pkg binary set the V8 young generation cap in two different places: the
// image through NODE_OPTIONS, the binary through options baked in at build time (a pkg binary ignores
// NODE_OPTIONS). Changing one without the other gives the two install paths different memory
// profiles, which is the kind of difference nobody notices until a support report compares them.

const test = require('node:test');
const assert = require('node:assert').strict;

const { readDockerfile } = require('./helpers/dockerfile');
const packageJson = require('../package.json');

function dockerNodeOptions() {
    let match = readDockerfile().match(/^ENV\s+NODE_OPTIONS=(.+)$/m);
    return match ? match[1].replace(/^"|"$/g, '').trim().split(/\s+/) : [];
}

// pkg takes V8 options without the leading dashes and with underscores, the way V8 itself accepts them
function pkgOption(name) {
    let prefix = `${name.replace(/-/g, '_')}=`;
    let option = (packageJson.pkg.options || []).find(entry => entry.startsWith(prefix));
    return option ? option.slice(prefix.length) : null;
}

test('Docker image and pkg binary use the same young generation cap', () => {
    let flag = dockerNodeOptions().find(entry => entry.startsWith('--max-semi-space-size='));
    assert.ok(flag, 'Dockerfile sets --max-semi-space-size in NODE_OPTIONS');

    let dockerValue = flag.split('=')[1];
    assert.equal(pkgOption('max-semi-space-size'), dockerValue);
    assert.equal(dockerValue, '16');
});
