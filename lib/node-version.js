'use strict';

// Which Node.js releases EmailEngine runs on. Requires nothing but the dependency-free
// lib/utils/version.js, because server.js asks before it requires anything else.
//
// Two thresholds, because the dependency tree has two:
//
// - MIN_NODE is the oldest release EmailEngine can start on at all. undici 8, which the main
//   thread and every worker load at startup, throws when it is loaded on anything older than
//   22.19 (it calls a zlib API Node 20 does not have), so below it server.js exits with a message
//   instead of letting the first worker die on a TypeError.
// - SUPPORTED_RANGES is what package.json `engines.node` declares, the range the bundled jsdom
//   (inside @postalsys/email-text-tools) declares. A release between the two starts and runs, and
//   the dashboard says it is outside the supported range. test/node-version-test.js keeps the
//   ranges equal to the engines field.

const { compareVersions } = require('./utils/version');

const MIN_NODE = '22.19.0';

// [major, minimum within that major], the last entry also admits every later major
const SUPPORTED_RANGES = [
    [22, '22.22.2'],
    [24, '24.15.0'],
    [26, '26.0.0']
];

// The engines.node form of SUPPORTED_RANGES
const SUPPORTED_RANGE_TEXT = SUPPORTED_RANGES.map(([, min], i) => (i === SUPPORTED_RANGES.length - 1 ? `>=${min}` : `^${min}`)).join(' || ');

// What an operator reads when the version is not supported
// ("22.x from 22.22.2, 24.x from 24.15.0, or 26 and newer")
const SUPPORTED_RANGE_LABEL = SUPPORTED_RANGES.map(([major, min], i) =>
    i === SUPPORTED_RANGES.length - 1 ? `or ${major} and newer` : `${major}.x from ${min}`
).join(', ');

function normalize(version) {
    return String(version || '').replace(/^v/, '');
}

function inSupportedRange(version) {
    const major = Number(version.split('.')[0]);
    const last = SUPPORTED_RANGES[SUPPORTED_RANGES.length - 1];
    if (major >= last[0]) {
        return compareVersions(version, last[1]) >= 0;
    }
    const range = SUPPORTED_RANGES.find(([rangeMajor]) => rangeMajor === major);
    return !!range && compareVersions(version, range[1]) >= 0;
}

/**
 * How well EmailEngine supports a Node.js version
 * @param {string} version - A version such as process.versions.node ("22.19.0")
 * @returns {'unsupported'|'outside-range'|'ok'} 'unsupported' below MIN_NODE, 'outside-range' for
 *   a release that runs but is not in SUPPORTED_RANGES, 'ok' otherwise. A version that can not be
 *   read is 'ok': nothing is gained by refusing to start over a string we do not understand
 */
function nodeSupport(version) {
    const normalized = normalize(version);
    try {
        if (compareVersions(normalized, MIN_NODE) < 0) {
            return 'unsupported';
        }
        return inSupportedRange(normalized) ? 'ok' : 'outside-range';
    } catch (err) {
        return 'ok';
    }
}

// What an operator on a Debian or Ubuntu server with Node.js from NodeSource (the DigitalOcean one-click
// image included) runs to move to a supported release. The startup error and /admin/upgrade show it
const NODESOURCE_UPGRADE_COMMANDS = [
    'curl -fsSL https://deb.nodesource.com/setup_24.x | sudo bash -',
    'sudo apt-get install -y nodejs',
    'sudo systemctl restart emailengine'
];

/**
 * The commands an operator runs to move to a supported Node.js release, for the startup error
 * @returns {string}
 */
function nodeUpgradeHint() {
    return [
        'To upgrade Node.js on a Debian or Ubuntu server that installed it from NodeSource (this includes the',
        'DigitalOcean one-click image), run:',
        '',
        ...NODESOURCE_UPGRADE_COMMANDS.map(command => `    ${command}`),
        '',
        'The EmailEngine binaries and the Docker image carry their own Node.js and are not affected.'
    ].join('\n');
}

/**
 * What the admin UI shows about the Node.js release it runs on
 * @param {string} version - A version such as process.versions.node
 * @param {boolean} [packaged] - A pkg binary, which carries its own Node.js: there is nothing for
 *   its operator to upgrade but EmailEngine, so it is never flagged
 * @returns {{version: string, supported: string, upgradeCommands: string[], packaged: boolean, outsideRange: boolean}}
 */
function nodeRuntimeView(version, packaged) {
    return {
        version: normalize(version),
        supported: SUPPORTED_RANGE_LABEL,
        upgradeCommands: NODESOURCE_UPGRADE_COMMANDS,
        packaged: !!packaged,
        // 'unsupported' never renders: the process would not have started
        outsideRange: !packaged && nodeSupport(version) !== 'ok'
    };
}

module.exports = { nodeRuntimeView, MIN_NODE, SUPPORTED_RANGE_TEXT, SUPPORTED_RANGE_LABEL, nodeSupport, nodeUpgradeHint };
