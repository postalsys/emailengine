'use strict';

require('dotenv').config();
try {
    process.chdir(__dirname);
} catch (err) {
    // ignore
}

process.title = 'emailengine-encrypt';

const { redis } = require('./lib/db');
const config = require('wild-config');
const { encrypt, decrypt, parseEncryptedData } = require('./lib/encrypt');
const { encryptedKeys } = require('./lib/settings');
const getSecret = require('./lib/get-secret');

const DECRYPT_PASSWORDS = [].concat(config.decrypt || []);

async function processSecret(value, encryptSecret) {
    let lastErr = false;
    let decrypted = value;

    for (let password of DECRYPT_PASSWORDS) {
        try {
            decrypted = decrypt(value, password);
            if (password === encryptSecret) {
                // nothing was changed
                return value;
            }
            break;
        } catch (err) {
            lastErr = err;
        }
    }

    let parsed = parseEncryptedData(decrypted);
    if (parsed.format !== 'cleartext') {
        // was not able to decrypt
        if (encryptSecret) {
            try {
                decrypted = decrypt(value, encryptSecret);
                // did not throw, so the value is already encrypted with the new password
                return value;
            } catch (err) {
                // ignore
            }
        }

        throw lastErr || new Error('Could not decrypt encrypted password');
    }

    if (encryptSecret) {
        // encrypt
        return encrypt(decrypted, encryptSecret);
    }

    // return plaintext
    return decrypted;
}

async function main() {
    console.error('EmailEngine account encryption tool');

    const encryptSecret = await getSecret();

    if (!encryptSecret && !DECRYPT_PASSWORDS.length) {
        console.error('Usage:');
        console.error('  emailengine encrypt --dbs.redis="redis://url" --service.secret="new-pass" --decrypt="old-pass"');
        console.error('Where');
        console.error(' --dbs.redis is a Redis configuration URL');
        console.error(' --service.secret is the secret value to use for encryption.');
        console.error('   Leave empty to remove encryption.');
        console.error(' --decrypt is the old secret value. Not needed if current passwords are not encrypted.');
        console.error('   You can set this value multiple times if accounts are enrypted with different secrets.');
        return;
    }

    // convert settings
    for (let key of encryptedKeys) {
        let value = await redis.hget('settings', key);
        if (value && typeof value === 'string') {
            try {
                let updated = await processSecret(value, encryptSecret);
                if (updated !== value) {
                    await redis.hset('settings', key, updated);
                    console.log(`${key}: Updated setting value`);
                }
            } catch (err) {
                console.error(`${key}: Failed to process setting value`);
                console.error(err);
            }
        }
    }

    let updatedAccounts = 0;
    let accounts = await redis.smembers('ia:accounts');
    for (let account of accounts) {
        let accountData = await redis.hgetall(`iad:${account}`);
        if (!accountData) {
            continue;
        }

        let updates = {};
        let updated = false;
        for (let key of ['imap', 'smtp', 'oauth2']) {
            if (!accountData[key]) {
                continue;
            }

            try {
                accountData[key] = JSON.parse(accountData[key]);
            } catch (err) {
                console.error(`Failed to parse ${key} for ${account}`);
                console.error(err);
                continue;
            }

            if (!accountData[key]) {
                continue;
            }

            let changes = false;

            for (let subKey of ['pass', 'accessToken', 'refreshToken']) {
                if (accountData[key].auth && accountData[key].auth[subKey]) {
                    try {
                        let value = await processSecret(accountData[key].auth[subKey], encryptSecret);
                        if (value !== accountData[key].auth[subKey]) {
                            accountData[key].auth[subKey] = value;
                            changes = true;
                        }
                    } catch (err) {
                        console.error(`Could not process "${key}.auth.${subKey}" for ${account}. Check decryption secrets.`);
                    }
                }
            }

            for (let subKey of ['accessToken', 'refreshToken']) {
                if (accountData[key] && accountData[key][subKey]) {
                    try {
                        let value = await processSecret(accountData[key][subKey], encryptSecret);
                        if (value !== accountData[key][subKey]) {
                            accountData[key][subKey] = value;
                            changes = true;
                        }
                    } catch (err) {
                        console.error(`Could not process "${key}.${subKey}" for ${account}. Check decryption secrets.`);
                    }
                }
            }

            if (changes) {
                updates[key] = JSON.stringify(accountData[key]);
                updated = true;
            }
        }

        if (updated) {
            let result = await redis.hmset(`iad:${account}`, updates);
            if (result === 'OK') {
                console.log(`${account}: updated`);
            } else {
                console.log(`${account}: Unexpected response from DB: ${result}`);
            }
            updatedAccounts++;
        }
    }

    console.log(`Updated ${updatedAccounts}/${accounts.length} accounts`);
}

main()
    .then(() => process.exit(0))
    .catch(err => {
        console.error(err);
        process.exit(1);
    })
    .finally();
