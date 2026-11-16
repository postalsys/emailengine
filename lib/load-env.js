'use strict';

// Loads `.env` from the working directory into process.env with Node's own parser
// (process.loadEnvFile, Node 21.7+), which replaced the dotenv package. Variables that are
// already set are never overwritten, the same as dotenv did.
//
// Dependency-free on purpose: server.js loads it before it checks the Node.js version, so it has
// to load on any release. On a release without process.loadEnvFile it does nothing, and the
// version check that follows tells the operator to upgrade.

/**
 * Loads an env file, if there is one.
 *
 * A missing file is the normal case and is silent. A file that exists but cannot be read is
 * reported on stderr and otherwise ignored, as dotenv ignored it: the instance then starts with
 * the environment it was given rather than not at all.
 *
 * @param {string} [path='.env'] Resolved against the working directory
 * @returns {boolean} Whether a file was loaded
 */
function loadEnvFile(path = '.env') {
    if (typeof process.loadEnvFile !== 'function') {
        return false;
    }
    try {
        process.loadEnvFile(path);
        return true;
    } catch (err) {
        if (err.code !== 'ENOENT') {
            process.stderr.write(`Could not load ${path}: ${err.message}\n`);
        }
        return false;
    }
}

/**
 * Loads `.env` once per process, however many modules ask. Worker threads share process.env with
 * the main thread, so the marker also keeps them from loading the file again.
 */
function loadEnvOnce() {
    if (!process.env.EE_ENV_LOADED) {
        loadEnvFile();
        process.env.EE_ENV_LOADED = 'true';
    }
}

module.exports = { loadEnvFile, loadEnvOnce };
