'use strict';

const config = require('wild-config');
const vault = require('node-vault');
const logger = require('./logger');

config.service = config.service || {};

const ENCRYPT_SECRET = process.env.EENGINE_SECRET || config.service.secret;

const VAULT_ADDR = process.env.VAULT_ADDR;
const VAULT_ROLE_ID = process.env.VAULT_ROLE_ID;
const VAULT_SECRET_ID = process.env.VAULT_SECRET_ID;
const VAULT_PATH = process.env.VAULT_PATH;
const VAULT_KEY = process.env.VAULT_KEY || 'secret';

const cache = new Map();

const vaultClient =
    VAULT_ADDR && VAULT_ROLE_ID && VAULT_SECRET_ID && VAULT_PATH
        ? vault({
              apiVersion: 'v1',
              endpoint: VAULT_ADDR
          })
        : false;

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
            console.error(`Retrieved Vault token for role ${VAULT_ROLE_ID}`);
        } else {
            logger.info({ msg: 'Retrieved Vault token', role_id: VAULT_ROLE_ID });
        }
    }

    return vaultClient;
}

async function getSecret(opts) {
    if (cache.has('secret')) {
        return cache.get('secret');
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

        cache.set('secret', secret);
        return secret;
    }

    return ENCRYPT_SECRET;
}

module.exports = getSecret;
