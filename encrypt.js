'use strict';

require('dotenv').config();
try {
    process.chdir(__dirname);
} catch (err) {
    // ignore
}

process.title = 'imapapi-encrypt';

const { redis } = require('./lib/db');
const config = require('wild-config');
const { encrypt, decrypt, parseEncryptedData } = require('./lib/encrypt');

config.service = config.service || {};

const ENCRYPT_PASSWORD = process.env.IMAPAPI_SECRET || config.service.secret;
const DECRYPT_PASSWRODS = [].concat(config.decrypt || []);

async function processSecret(value) {
    let lastErr = false;
    let decrypted = value;

    for (let password of DECRYPT_PASSWRODS.concat(ENCRYPT_PASSWORD || [])) {
        try {
            decrypted = decrypt(value, password);
            if (password === ENCRYPT_PASSWORD) {
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
        throw lastErr || new Error('Could not decrypt encrypted password');
    }

    if (ENCRYPT_PASSWORD) {
        // encrypt
        return encrypt(decrypted, ENCRYPT_PASSWORD);
    }

    // return plaintext
    return decrypted;
}

async function main() {
    console.error('IMAP API account encryption tool');

    if (!ENCRYPT_PASSWORD && !DECRYPT_PASSWRODS.length) {
        console.error('Usage:');
        console.error('  imapapi encrypt --dbs.redis="redis://url" --service.secret="new-pass" --decrypt="old-pass"');
        console.error('Where');
        console.error(' --dbs.redis is a Redis configuration URL');
        console.error(' --service.secret is the secret value to use for encryption.');
        console.error('   Leave empty to remove encryption.');
        console.error(' --decrypt is the old secret value. Not needed if current passwords are not encrypted.');
        console.error('   You can set this value multiple times if accounts are enrypted with different secrets.');
        return;
    }

    let accounts = await redis.smembers('ia:accounts');
    for (let account of accounts) {
        let accountData = await redis.hgetall(`iad:${account}`);
        if (!accountData) {
            continue;
        }

        let updates = {};
        let updated = false;
        for (let key of ['imap', 'smtp']) {
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
            for (let subKey of ['pass', 'accessToken']) {
                if (accountData[key].auth && accountData[key].auth[subKey]) {
                    try {
                        let value = await processSecret(accountData[key].auth[subKey]);
                        if (value !== accountData[key].auth[subKey]) {
                            accountData[key].auth[subKey] = value;
                            changes = true;
                        }
                    } catch (err) {
                        console.error(`Could not process "${key}.auth.${subKey}" for ${account}. Check decryption secrets.`);
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
        } else {
            console.log(`${account}: not changed`);
        }
    }
}

main()
    .then(() => process.exit(0))
    .catch(err => {
        console.error(err);
        process.exit(1);
    })
    .finally();
