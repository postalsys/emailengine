'use strict';

// The oldest Node.js release the dependency tree supports, matching `engines.node` in package.json
// (test/node-version-test.js keeps the two in step). Dependency-free, because server.js checks it
// before it requires anything else.

const MIN_SUPPORTED_NODE = '20.19.0';

/**
 * Whether a Node.js version is older than MIN_SUPPORTED_NODE
 * @param {string} version - A version such as process.versions.node ("20.18.1")
 * @returns {boolean} True when the version is older
 */
function isBelowSupportedNode(version) {
    const parse = value =>
        String(value || '')
            .replace(/^v/, '')
            .split('.')
            .map(part => Number.parseInt(part, 10) || 0);

    const actual = parse(version);
    const minimum = parse(MIN_SUPPORTED_NODE);
    for (let i = 0; i < 3; i++) {
        if ((actual[i] || 0) !== minimum[i]) {
            return (actual[i] || 0) < minimum[i];
        }
    }
    return false;
}

module.exports = { MIN_SUPPORTED_NODE, isBelowSupportedNode };
