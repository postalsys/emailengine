'use strict';

require('./load-env').loadEnvOnce();

const config = require('@zone-eu/wild-config');
const { readEnvValue } = require('./read-env-value');

config.service = config.service || {};

const ENCRYPT_SECRET = readEnvValue('EENGINE_SECRET') || config.service.secret;

async function getSecret() {
    return ENCRYPT_SECRET;
}

module.exports = getSecret;
