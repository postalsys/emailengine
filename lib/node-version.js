'use strict';

// The oldest Node.js release the dependency tree supports, matching `engines.node` in package.json
// (test/node-version-test.js keeps the two in step). Requires nothing but the dependency-free
// lib/utils/version.js, because server.js checks it before it requires anything else.

const MIN_SUPPORTED_NODE = '20.19.0';

const { compareVersions } = require('./utils/version');

/**
 * Whether a Node.js version is older than MIN_SUPPORTED_NODE
 * @param {string} version - A version such as process.versions.node ("20.18.1")
 * @returns {boolean} True when the version is older, false for one that can not be read
 */
function isBelowSupportedNode(version) {
    try {
        return compareVersions(String(version || '').replace(/^v/, ''), MIN_SUPPORTED_NODE) < 0;
    } catch (err) {
        return false;
    }
}

module.exports = { MIN_SUPPORTED_NODE, isBelowSupportedNode };
