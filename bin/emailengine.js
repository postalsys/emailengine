#!/usr/bin/env node
/* eslint global-require: 0 */
'use strict';

const packageData = require('../package.json');
const fs = require('fs');
const pathlib = require('path');
const settings = require('../lib/settings');
const { checkLicense } = require('../lib/tools');
const pbkdf2 = require('@phc/pbkdf2');
const { PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST, generateWebhookTable } = require('../lib/consts');

const argv = require('minimist')(process.argv.slice(2));
const msgpack = require('msgpack5')();
const crypto = require('crypto');

function run() {
    let cmd = ((argv._ && argv._[0]) || '').toLowerCase();
    if (!cmd) {
        if (argv.version || argv.v) {
            cmd = 'version';
        }

        if (argv.help || argv.h) {
            cmd = 'help';
        }
    }

    switch (cmd) {
        case 'encrypt':
            process.title = 'emailengine-encrypt';
            // encrypt account passwords
            require('../encrypt');
            break;

        case 'scan':
            process.title = 'emailengine-scan';
            // Scan Redis keys
            require('../scan');
            break;

        case 'password':
            {
                // Update admin password
                let password = argv.password || argv.p || crypto.randomBytes(16).toString('hex');

                if (!password || typeof password !== 'string' || password.length < 8) {
                    console.error('Password must be at least 8 characters');
                    return process.exit(1);
                }

                let updatePassword = async () => {
                    let passwordHash = await pbkdf2.hash(password, {
                        iterations: PDKDF2_ITERATIONS,
                        saltSize: PDKDF2_SALT_SIZE,
                        digest: PDKDF2_DIGEST
                    });

                    let authData = await settings.get('authData');

                    authData = authData || {};
                    authData.user = authData.user || 'admin';
                    authData.password = passwordHash;
                    authData.passwordVersion = Date.now();

                    await settings.set('authData', authData);
                    await settings.set('totpEnabled', false);
                    await settings.set('totpSeed', false);

                    return { password, passwordHash };
                };

                updatePassword()
                    .then(res => {
                        let returnValue = argv.hash || argv.r ? Buffer.from(res.passwordHash).toString('base64url') : res.password;
                        process.stdout.write(returnValue);
                        return process.exit(0);
                    })
                    .catch(err => {
                        console.error('Failed to process account password');
                        console.error(err);
                        return process.exit(1);
                    });
            }
            break;

        case 'help':
            // Show version
            fs.readFile(pathlib.join(__dirname, '..', 'help.txt'), (err, helpText) => {
                if (err) {
                    console.error('Failed to load help information');
                    console.error(err);
                    return process.exit(1);
                }
                console.error(helpText.toString().trim());
                process.exit();
            });
            break;

        case 'version':
            // Show version
            console.log(`EmailEngine v${packageData.version} (${packageData.license})`);
            return process.exit();

        case 'license':
            {
                let licenseCmd = ((argv._ && argv._[1]) || '').toLowerCase();
                if (licenseCmd === 'export') {
                    return settings
                        .exportLicense()
                        .then(license => {
                            process.stdout.write(license);
                            return process.exit(0);
                        })
                        .catch(err => {
                            console.error('Failed to load license information');
                            console.error(err);
                            return process.exit(1);
                        });
                }

                if (licenseCmd === 'import') {
                    return settings
                        .importLicense((argv.license || argv.l || '').toString(), checkLicense)
                        .then(result => {
                            if (!result) {
                                console.error('License key was not imported');
                            } else {
                                console.error('License key was imported');
                            }
                            return process.exit(0);
                        })
                        .catch(err => {
                            console.error(`Failed to import license information${err.code ? ` [${err.code}]` : ''}`);
                            console.error(err);
                            return process.exit(1);
                        });
                }

                fs.readFile(pathlib.join(__dirname, '..', 'LICENSE_EMAILENGINE.txt'), (err, licenseComm) => {
                    if (err) {
                        console.error('Failed to load license information');
                        console.error(err);
                        return process.exit(1);
                    }

                    console.error('EmailEngine License');
                    console.error('===================');

                    // if only stdout is read, only this line is is seen:
                    process.stdout.write(`EmailEngine v${packageData.version}`);

                    console.error(`\n(c) 2020-${new Date().getFullYear()} Postal Systems`);
                    console.error(`${packageData.license}, full text follows`);
                    console.error('');

                    console.error('-'.repeat(78));
                    console.error('');

                    console.error(licenseComm.toString().trim());
                    console.error('-'.repeat(78));
                    console.error('');

                    process.exit();
                });
            }
            break;

        case 'tokens':
            {
                const tokens = require('../lib/tokens');
                let tokensCmd = ((argv._ && argv._[1]) || '').toLowerCase();
                switch (tokensCmd) {
                    case 'issue':
                        {
                            let allowedScopes = ['*', 'api', 'metrics', 'smtp', 'imap-proxy'];
                            let scopes = []
                                .concat(argv.scope || [])
                                .concat(argv.s || [])
                                .map(entry => (entry || '').toString().toLowerCase());

                            if (!scopes.length) {
                                scopes = ['*'];
                            }

                            for (let scope of scopes) {
                                if (!allowedScopes.includes(scope)) {
                                    console.error(`Unknown scope: ${scope}`);
                                    console.error(`Allowed scopes: "${allowedScopes.join('", "')}"`);
                                    process.exit(1);
                                }
                            }

                            let description = (argv.description || argv.d || '').toString();
                            if (!description) {
                                description = `Generated at ${new Date().toISOString()}`;
                            }
                            let account = argv.account || argv.a || '';
                            tokens
                                .provision({
                                    account,
                                    description,
                                    scopes,
                                    nolog: true
                                })
                                .then(token => {
                                    process.stdout.write(token);
                                    process.exit();
                                })
                                .catch(err => {
                                    console.error(err);
                                    process.exit(1);
                                });
                        }
                        break;

                    case 'export':
                        {
                            let token = (argv.token || argv.t || '').toString();
                            tokens
                                .getRawData(token)
                                .then(tokenData => {
                                    let encoded = msgpack.encode(tokenData);
                                    process.stdout.write(encoded.toString('base64url'));
                                    process.exit();
                                })
                                .catch(err => {
                                    console.error(err);
                                    process.exit(1);
                                });
                        }
                        break;

                    case 'import':
                        {
                            let rawToken = (argv.token || argv.t || '').toString();
                            let tokenData = msgpack.decode(Buffer.from(rawToken, 'base64url'));
                            tokens
                                .setRawData(tokenData)
                                .then(result => {
                                    if (!result) {
                                        console.error('Token was not imported');
                                    } else {
                                        console.error('Token was imported');
                                    }
                                    process.exit();
                                })
                                .catch(err => {
                                    console.error(err);
                                    process.exit(1);
                                });
                        }
                        break;

                    default:
                        console.error('Future feature');
                        break;
                }
            }
            break;

        case 'webhooks':
            generateWebhookTable();
            process.exit(1);
            break;

        default:
            // run normally
            require('../server');
            break;
    }
}

run();
