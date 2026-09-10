'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it).
//
// What the TLS suites share: a stand-in for the certificate library, and the reset of the
// settings and environment variables the certificate catalog reads. Each suite used to carry its
// own copy of the stub and its own, shorter, list of variables to clear - so a case that set
// EENGINE_IMAPPROXY_TLS_CERT leaked into every case after it in the suites that only cleared the
// SMTP pair, and the leak read as a catalog bug.

const settings = require('../../lib/settings');
const { LISTENERS, TLS_CERTIFICATE_SETTINGS } = require('../../lib/tls/listeners');

// Every environment variable the catalog turns into material, for every listener
const TLS_ENV_KEYS = LISTENERS.flatMap(listener => ['CERT', 'KEY', 'CA', 'PASSPHRASE'].map(suffix => `${listener.envPrefix}${suffix}`));

/**
 * A certificate handler that answers from a fixed map, standing in for @postalsys/certs.
 *
 * @param {Object} records Hostname to `{ cert, privateKey }`
 * @returns {Object} Something with getCertificate()
 */
function fakeCerts(records) {
    return {
        async getCertificate(hostname) {
            const record = (records || {})[hostname];
            return record ? Object.assign({ status: 'valid', ca: [] }, record) : false;
        }
    };
}

/**
 * Puts material into a listener's environment prefix, the way an operator does.
 *
 * @param {string} key Listener key
 * @param {Object} material `{ cert, privateKey }`
 */
function setEnvMaterial(key, material) {
    const listener = LISTENERS.find(entry => entry.key === key);
    process.env[`${listener.envPrefix}CERT`] = material.cert;
    process.env[`${listener.envPrefix}KEY`] = material.privateKey;
}

function clearTlsEnv() {
    for (const key of TLS_ENV_KEYS) {
        delete process.env[key];
    }
}

/**
 * The settings the catalog and the listeners read, back to a known state.
 *
 * @param {Object} [values] Overrides; `serviceUrl` defaults to https://mail.example.com
 */
async function resetTlsSettings(values) {
    const defaults = { serviceUrl: 'https://mail.example.com', tlsHostnames: null, tlsProvisioning: null };
    for (const key of TLS_CERTIFICATE_SETTINGS) {
        defaults[key] = null;
    }
    for (const [key, value] of Object.entries(Object.assign(defaults, values || {}))) {
        await settings.set(key, value);
    }
}

module.exports = { TLS_ENV_KEYS, fakeCerts, setEnvMaterial, clearTlsEnv, resetTlsSettings };
