'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config({ quiet: true });
    process.env.EE_ENV_LOADED = 'true';
}

try {
    process.chdir(__dirname);
} catch (err) {
    // ignore
}

const { redis } = require('./lib/db');
const config = require('@zone-eu/wild-config');
const { encrypt, decrypt, parseEncryptedData } = require('./lib/encrypt');
const { encryptedKeys } = require('./lib/settings');
const getSecret = require('./lib/get-secret');
const msgpack = require('msgpack5')();

const { REDIS_PREFIX, ENCRYPTED_APP_KEYS } = require('./lib/consts');
const { Settings: CertSettings } = require('@postalsys/certs/lib/settings');

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
        console.error('   You can set this value multiple times if accounts are encrypted with different secrets.');
        return;
    }

    // convert settings
    for (let key of encryptedKeys) {
        let value = await redis.hget(`${REDIS_PREFIX}settings`, key);
        if (value && typeof value === 'string') {
            try {
                let updated = await processSecret(value, encryptSecret);
                if (updated !== value) {
                    await redis.hset(`${REDIS_PREFIX}settings`, key, updated);
                    console.log(`${key}: Updated setting value`);
                }
            } catch (err) {
                console.error(`${key}: Failed to process setting value`);
                console.error(err);
            }
        }
    }

    let updatedAccounts = 0;
    let accounts = await redis.smembers(`${REDIS_PREFIX}ia:accounts`);
    for (let account of accounts) {
        let accountData = await redis.hgetall(`${REDIS_PREFIX}iad:${account}`);
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
            let result = await redis.hmset(`${REDIS_PREFIX}iad:${account}`, updates);
            if (result === 'OK') {
                console.log(`${account}: updated`);
            } else {
                console.log(`${account}: Unexpected response from DB: ${result}`);
            }
            updatedAccounts++;
        }
    }

    console.log(`Updated ${updatedAccounts}/${accounts.length} accounts`);

    let updatedGateways = 0;
    // NB: the index set is `gateways`, not `ia:gateways` - see lib/gateway.js. Reading the wrong
    // key made this loop report `0/0` on every rotation while leaving gateway passwords encrypted
    // with the old secret.
    let gateways = await redis.smembers(`${REDIS_PREFIX}gateways`);
    for (let gateway of gateways) {
        let pass = await redis.hget(`${REDIS_PREFIX}gateway:${gateway}`, 'pass');
        if (!pass) {
            continue;
        }

        try {
            let value = await processSecret(pass, encryptSecret);
            if (value !== pass) {
                let result = await redis.hmset(`${REDIS_PREFIX}gateway:${gateway}`, { pass: value });
                if (result === 'OK') {
                    console.log(`Gateway ${gateway}: updated`);
                } else {
                    console.log(`Gateway ${gateway}: Unexpected response from DB: ${result}`);
                }
                updatedGateways++;
            }
        } catch (err) {
            console.error(`Could not process "pass" for ${gateway}. Check decryption secrets.`);
        }
    }

    console.log(`Updated ${updatedGateways}/${gateways.length} SMTP gateways`);

    let updatedApps = 0;
    let apps = await redis.smembers(`${REDIS_PREFIX}oapp:i`);
    for (let app of apps) {
        let appBuf = await redis.hgetBuffer(`${REDIS_PREFIX}oapp:c`, `${app}:data`);
        if (!appBuf) {
            continue;
        }

        let entry;
        try {
            entry = msgpack.decode(appBuf);
        } catch (err) {
            console.log(`OAuth2 App ${app}: failed to parse`);
            continue;
        }

        try {
            let appUpdated = false;
            for (let key of ENCRYPTED_APP_KEYS) {
                if (entry[key]) {
                    let value = await processSecret(entry[key], encryptSecret);
                    if (value !== entry[key]) {
                        entry[key] = value;
                        appUpdated = true;
                    }
                }
            }

            if (appUpdated) {
                let result = await redis.hmset(`${REDIS_PREFIX}oapp:c`, { [`${app}:data`]: msgpack.encode(entry) });
                if (result === 'OK') {
                    console.log(`OAuth2 App ${app}: updated`);
                } else {
                    console.log(`OAuth2 App ${app}: Unexpected response from DB: ${result}`);
                }
                updatedApps++;
            }
        } catch (err) {
            console.error(`Could not process encrypted values for OAuth2 App ${app}. Check decryption secrets.`);
        }
    }

    console.log(`Updated ${updatedApps}/${apps.length} OAuth2 apps`);

    // TLS private keys managed by @postalsys/certs. These live in the module's own hash, not in the
    // EmailEngine settings hash, so they need their own pass - without it a rotation leaves the ACME
    // account key and every domain key readable only with the old secret, and TLS fails on the next
    // renewal with no self-healing path. Every field in that hash is msgpack encoded; only the ACME
    // account's `privateKey` and the `domain:<name>:privateKey` entries hold encrypted values.
    let updatedCerts = 0;
    // Ask the library for the key instead of rebuilding it here: the namespace it is constructed
    // with is `${REDIS_PREFIX}`, and it appends its own separator, so the hash is
    // `certs:settings` unprefixed but `<prefix>::certs:settings` when EENGINE_REDIS_PREFIX is set.
    let certsKey = CertSettings.create({ namespace: `${REDIS_PREFIX}` }).getKey('settings');
    let certEntries = await redis.hgetallBuffer(certsKey);
    for (let field of Object.keys(certEntries || {})) {
        let isAcmeAccount = /^account:/.test(field);
        let isDomainKey = /^domain:.*:privateKey$/.test(field);
        if (!isAcmeAccount && !isDomainKey) {
            continue;
        }

        let entry;
        try {
            entry = msgpack.decode(certEntries[field]);
        } catch (err) {
            console.log(`Certificate entry ${field}: failed to parse`);
            continue;
        }

        try {
            let value;
            if (isAcmeAccount) {
                if (!entry || !entry.privateKey) {
                    continue;
                }
                let updated = await processSecret(entry.privateKey, encryptSecret);
                if (updated === entry.privateKey) {
                    continue;
                }
                entry.privateKey = updated;
                value = entry;
            } else {
                if (!entry) {
                    continue;
                }
                let updated = await processSecret(entry, encryptSecret);
                if (updated === entry) {
                    continue;
                }
                value = updated;
            }

            let result = await redis.hmset(certsKey, { [field]: msgpack.encode(value) });
            if (result === 'OK') {
                console.log(`Certificate entry ${field}: updated`);
            } else {
                console.log(`Certificate entry ${field}: Unexpected response from DB: ${result}`);
            }
            updatedCerts++;
        } catch (err) {
            console.error(`Could not process "${field}". Check decryption secrets.`);
        }
    }

    console.log(`Updated ${updatedCerts} TLS private keys`);
}

main()
    .then(() => process.exit(0))
    .catch(err => {
        console.error(err);
        process.exit(1);
    })
    .finally();
