'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config(); // eslint-disable-line global-require
    process.env.EE_ENV_LOADED = 'true';
}

const config = require('wild-config');
const vault = require('node-vault');
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

const VAULT_ADDR = readEnvValue('VAULT_ADDR');
const VAULT_ROLE_ID = readEnvValue('VAULT_ROLE_ID');
const VAULT_SECRET_ID = readEnvValue('VAULT_SECRET_ID');
const VAULT_PATH = readEnvValue('VAULT_PATH');
const VAULT_KEY = readEnvValue('VAULT_KEY') || 'secret';

const vaultClient =
    VAULT_ADDR && VAULT_ROLE_ID && VAULT_SECRET_ID && VAULT_PATH
        ? vault({
              apiVersion: 'v1',
              endpoint: VAULT_ADDR
          })
        : false;

const cache = new Map();

async function getVaultClient(opts) {
    if (!vaultClient) {
        return false;
    }

    if (!vaultClient.token) {
        const result = await vaultClient.approleLogin({
            role_id: VAULT_ROLE_ID,
            secret_id: VAULT_SECRET_ID
        });
        vault.token = result.auth.client_token;
        if (opts && opts.text) {
            console.error(`Retrieved access token from Vault for role ${VAULT_ROLE_ID}`);
        } else {
            logger.info({ msg: 'Retrieved access token from Vault', role_id: VAULT_ROLE_ID });
        }
    }

    return vaultClient;
}

async function getSecret(opts) {
    if (cache.has('secret')) {
        return cache.get('secret');
    }

    if (process.env._VAULT_SECRET) {
        if (opts && opts.text) {
            console.error(`Using cached encryption secret from Vault`);
        } else {
            logger.info({ msg: 'Using cached encryption secret from Vault', role_id: VAULT_ROLE_ID });
        }
        cache.set('secret', process.env._VAULT_SECRET);
        return process.env._VAULT_SECRET;
    }

    // check vault
    let vaultClient = await getVaultClient(opts);
    if (vaultClient) {
        let vaultRes = await vaultClient.read(VAULT_PATH);
        let secret = vaultRes && vaultRes.data && vaultRes.data.data && vaultRes.data.data[VAULT_KEY];

        if (opts && opts.text) {
            console.error(`Retrieved encryption secret from Vault for role ${VAULT_ROLE_ID}`);
        } else {
            logger.info({ msg: 'Retrieved encryption secret from Vault', role_id: VAULT_ROLE_ID });
        }

        process.env._VAULT_SECRET = secret;
        cache.set('secret', process.env._VAULT_SECRET);
        return secret;
    }

    return ENCRYPT_SECRET;
}

module.exports = getSecret;
