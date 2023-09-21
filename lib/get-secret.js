'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config(); // eslint-disable-line global-require
    process.env.EE_ENV_LOADED = 'true';
}

const config = require('wild-config');
const fs = require('fs');
const logger = require('./logger');

config.service = config.service || {};

// duplicat function declaration to avoid requireing tools.js
const readEnvValue = key => {
    if (key in process.env) {
        return process.env[key];
    }

    if (typeof process.env[`${key}_FILE`] === 'string' && process.env[`${key}_FILE`]) {
        try {
            // try to load from file
            process.env[key] = fs.readFileSync(process.env[`${key}_FILE`], 'utf-8').replace(/\r?\n$/, '');
            logger.trace({ msg: 'Loaded environment value from file', key, file: process.env[`${key}_FILE`] });
        } catch (err) {
            logger.error({ msg: 'Failed to load environment value from file', key, file: process.env[`${key}_FILE`], err });
            process.env[key] = '';
        }
        return process.env[key];
    }
};

const ENCRYPT_SECRET = readEnvValue('EENGINE_SECRET') || config.service.secret;

async function getSecret() {
    return ENCRYPT_SECRET;
}

module.exports = getSecret;
