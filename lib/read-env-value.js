'use strict';

// Split out of lib/tools.js so modules that resolve configuration during their own initialization
// can read it without pulling in the whole utility surface (and without the import cycle that
// would create). Still re-exported from lib/tools.js, which is where most callers reach it.

const Fs = require('fs');
const logger = require('./logger');

/**
 * Reads an environment value, falling back to the contents of the `<KEY>_FILE` variable.
 *
 * The file form is how secrets are handed to containerized deployments; the resolved value is
 * written back into process.env so the file is read at most once.
 *
 * @param {string} key - Environment variable name
 * @returns {string|undefined} The value, or undefined when neither form is set
 */
function readEnvValue(key) {
    if (key in process.env) {
        return process.env[key];
    }

    if (typeof process.env[`${key}_FILE`] === 'string' && process.env[`${key}_FILE`]) {
        try {
            // try to load from file
            process.env[key] = Fs.readFileSync(process.env[`${key}_FILE`], 'utf-8').replace(/\r?\n/g, '\n').trim();
            logger.trace({ msg: 'Loaded environment value from file', key, file: process.env[`${key}_FILE`] });
        } catch (err) {
            logger.error({ msg: 'Failed to load environment value from file', key, file: process.env[`${key}_FILE`], err });
            process.env[key] = '';
        }
        return process.env[key];
    }
}

module.exports = { readEnvValue };
