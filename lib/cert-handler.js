'use strict';

const { Certs } = require('@postalsys/certs');

const { redis } = require('./db');
const getSecret = require('./get-secret');
const { encrypt, decrypt } = require('./encrypt');
const { httpAgent } = require('./tools');
const { REDIS_PREFIX, ACME_ENVIRONMENT, ACME_DIRECTORY_URL, ACME_OVERRIDE_PARTIAL } = require('./consts');

/**
 * Builds the Let's Encrypt certificate handler.
 *
 * Three workers need one: the API worker, which is the only one that provisions, and the SMTP
 * server and the IMAP proxy, which read what it stored. Every argument is the same in all three, so
 * this exists rather than the same twenty lines written out three times. That is not only about
 * repetition: `environment` and `directoryUrl` belong inside the `acme` block, and two of the three
 * copies used to pass `environment` at the top level, where the constructor never reads it. Nothing
 * failed, because those two never provision, and nothing would have until one of them did.
 *
 * @param {Object} logger worker logger; the handler logs under `sub: 'acme'`
 * @returns {Object} a `Certs` instance
 */
function createCertHandler(logger) {
    if (ACME_OVERRIDE_PARTIAL) {
        // Nothing here can tell which of the two was meant - an operator rehearsing against staging
        // and one running a private CA under the default account name are the same instruction from
        // here - so it is reported rather than repaired
        logger.warn({
            msg: 'Only one half of the ACME override is set, certificate orders will most likely be rejected',
            environment: ACME_ENVIRONMENT,
            directoryUrl: ACME_DIRECTORY_URL
        });
    }

    return new Certs({
        redis,
        namespace: `${REDIS_PREFIX}`,

        acme: {
            environment: ACME_ENVIRONMENT,
            directoryUrl: ACME_DIRECTORY_URL
        },

        // long-lived client, see LiveDispatcher in lib/tools.js
        dispatcher: httpAgent.live,

        logger: logger.child({ sub: 'acme' }),

        encryptFn: async value => {
            const encryptSecret = await getSecret();
            return encrypt(value, encryptSecret);
        },

        decryptFn: async value => {
            const encryptSecret = await getSecret();
            return decrypt(value, encryptSecret);
        }
    });
}

module.exports = { createCertHandler };
