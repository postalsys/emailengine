'use strict';

// Semantic version parsing and precedence (semver 2.0.0, section 11) for the two places EmailEngine
// compares versions: the update check against the latest GitHub release tag, and the license
// check's record of which version last validated. Both only ever see MAJOR.MINOR.PATCH with an
// optional pre-release, so ranges, wildcards and partial versions are deliberately not accepted.

const VERSION_RE = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/**
 * @param {string} version A version such as `2.84.2`, `v2.84.2` or `3.0.0-beta.1`
 * @returns {{ core: number[], prerelease: string[] } | null} The parsed version, or null if it is not one
 */
function parseVersion(version) {
    const match = typeof version === 'string' ? version.match(VERSION_RE) : null;
    if (!match) {
        return null;
    }
    return {
        core: [Number(match[1]), Number(match[2]), Number(match[3])],
        prerelease: match[4] ? match[4].split('.') : []
    };
}

function compareIdentifiers(a, b) {
    const aNumeric = /^\d+$/.test(a);
    const bNumeric = /^\d+$/.test(b);
    if (aNumeric && bNumeric) {
        return Math.sign(Number(a) - Number(b));
    }
    if (aNumeric !== bNumeric) {
        // numeric identifiers have lower precedence than alphanumeric ones
        return aNumeric ? -1 : 1;
    }
    return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Compares two versions by semver precedence. Build metadata is ignored.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} -1 when a is lower than b, 0 when equal, 1 when higher
 * @throws {TypeError} when either argument is not a version
 */
function compareVersions(a, b) {
    const va = parseVersion(a);
    const vb = parseVersion(b);
    if (!va || !vb) {
        throw new TypeError(`Invalid version: ${JSON.stringify(va ? b : a)}`);
    }

    for (let i = 0; i < 3; i++) {
        if (va.core[i] !== vb.core[i]) {
            return va.core[i] < vb.core[i] ? -1 : 1;
        }
    }

    // a version without a pre-release ranks above any pre-release of the same core version
    if (!va.prerelease.length || !vb.prerelease.length) {
        return Math.sign(vb.prerelease.length - va.prerelease.length);
    }

    const length = Math.min(va.prerelease.length, vb.prerelease.length);
    for (let i = 0; i < length; i++) {
        const result = compareIdentifiers(va.prerelease[i], vb.prerelease[i]);
        if (result) {
            return result;
        }
    }
    return Math.sign(va.prerelease.length - vb.prerelease.length);
}

module.exports = { parseVersion, compareVersions };
