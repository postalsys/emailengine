'use strict';

const { Certs } = require('@postalsys/certs');

const { redis } = require('./db');
const getSecret = require('./get-secret');
const { encrypt, decrypt } = require('./encrypt');
const { httpAgent } = require('./tools');
const { REDIS_PREFIX, ACME_ENVIRONMENT, ACME_DIRECTORY_URL } = require('./consts');

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
