'use strict';

// Split out of lib/tools.js so modules that resolve configuration during their own initialization
// can read it without pulling in the whole utility surface (and without the import cycle that
// would create). Still re-exported from lib/tools.js, which is where most callers reach it.

const Fs = require('fs');
const logger = require('./logger');

// The keys that lib/db.js and lib/get-secret.js used to resolve through private copies of this
// function. Those copies stripped a single trailing newline and nothing else, so for a file carrying
// any other surrounding whitespace the value they produced is not the value this helper produces.
// EENGINE_SECRET is the one that matters: a different secret means every stored credential fails to
// decrypt, and nothing can repair it automatically, because the old value is the one the data was
// encrypted with and only the operator knows whether the whitespace belongs to it. So the difference
// is reported rather than guessed at.
//
// The list is closed, not a registry to extend: no other key ever had the old behavior, so warning
// about one would claim a change that never happened, and no future key can acquire it, because
// test/read-env-value-guardrail-test.js fails on any module that re-implements the file fallback.
// It can be deleted outright once upgrading from a release before 2.82.1 is no longer supported.
const LEGACY_UNTRIMMED_KEYS = new Set(['EENGINE_SECRET', 'EENGINE_REDIS', 'REDIS_URL']);

/**
 * Reads an environment value, falling back to the contents of the `<KEY>_FILE` variable.
 *
 * The file form is how secrets are handed to containerized deployments; the resolved value is
 * written back into process.env so the file is read at most once. Surrounding whitespace is trimmed,
 * which is what makes `echo value > file` work, and line endings are normalized so a file written on
 * Windows resolves to the same value as one written anywhere else.
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
            const contents = Fs.readFileSync(process.env[`${key}_FILE`], 'utf-8');
            const value = contents.replace(/\r?\n/g, '\n').trim();
            process.env[key] = value;

            // What the private copies in lib/db.js and lib/get-secret.js resolved the same file to.
            // Neither the value nor the whitespace around it is logged: the key and the file are what
            // the operator needs to find it, and the value is what the warning exists to protect.
            const legacyValue = contents.replace(/\r?\n$/, '');
            if (LEGACY_UNTRIMMED_KEYS.has(key) && value !== legacyValue) {
                logger.warn({
                    msg: 'Environment value read from file carries whitespace that is now trimmed, so it resolves differently than in earlier releases. Set the variable itself rather than the file to keep the old value, as one given in the environment is used verbatim.',
                    key,
                    file: process.env[`${key}_FILE`]
                });
            }

            logger.trace({ msg: 'Loaded environment value from file', key, file: process.env[`${key}_FILE`] });
        } catch (err) {
            logger.error({ msg: 'Failed to load environment value from file', key, file: process.env[`${key}_FILE`], err });
            process.env[key] = '';
        }
        return process.env[key];
    }
}

module.exports = { readEnvValue };
