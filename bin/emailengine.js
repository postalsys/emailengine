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
const { Account } = require('../lib/account');
const getSecret = require('../lib/get-secret');
const { redis } = require('../lib/db');

const argv = require('minimist')(process.argv.slice(2));
const msgpack = require('msgpack5')();
const crypto = require('crypto');

// Command definitions for dynamic help generation
const COMMANDS = {
    '': {
        description: 'Start the EmailEngine server'
    },
    help: {
        description: 'Show help for a command'
    },
    version: {
        description: 'Show version number'
    },
    license: {
        description: 'Show license information',
        subcommands: {
            export: { description: 'Export license key for backup' },
            import: {
                description: 'Import license key',
                options: [{ name: '--license, -l', description: 'Encoded license key', type: 'string' }]
            }
        }
    },
    password: {
        description: 'Set or reset admin password',
        options: [
            { name: '--password, -p', description: 'Password to set (auto-generated if not provided)', type: 'string' },
            { name: '--hash, -r', description: 'Output password hash instead of plaintext', type: 'boolean' }
        ]
    },
    scan: {
        description: 'Scan Redis keyspace and output as CSV'
    },
    encrypt: {
        description: 'Manage field-level encryption for stored credentials',
        options: [{ name: '--decrypt', description: 'Previous secret for re-encryption (repeatable)', type: 'string' }]
    },
    tokens: {
        description: 'Manage API access tokens',
        subcommands: {
            issue: {
                description: 'Create a new access token',
                options: [
                    { name: '--description, -d', description: 'Token description', type: 'string' },
                    { name: '--scope, -s', description: 'Access scope', type: 'string', default: '*' },
                    { name: '--account, -a', description: 'Limit token to specific account', type: 'string' }
                ]
            },
            export: {
                description: 'Export token for backup',
                options: [{ name: '--token, -t', description: 'Token to export', type: 'string' }]
            },
            import: {
                description: 'Import previously exported token',
                options: [{ name: '--token, -t', description: 'Exported token data', type: 'string' }]
            }
        }
    },
    export: {
        description: 'Export account data including credentials',
        options: [{ name: '--account, -a', description: 'Account ID to export', type: 'string' }]
    },
    'check-bounce': {
        description: 'Analyze a bounce email and classify it',
        options: [{ name: '--file, -f', description: 'Path to EML file', type: 'string' }],
        example: 'emailengine check-bounce /path/to/bounce.eml'
    }
};

const GLOBAL_OPTIONS = [
    { name: '-h, --help', description: 'Show this help message' },
    { name: '--dbs.redis', description: 'Redis connection URL', type: 'string', group: 'General' },
    { name: '--workers.imap', description: 'Number of IMAP worker threads', type: 'number', default: 4, group: 'General' },
    { name: '--settings', description: 'Pre-configured settings as JSON', type: 'json-string', group: 'General' },
    { name: '--service.secret', description: 'Secret key for encrypting stored credentials', type: 'string', group: 'General' },
    { name: '--service.commandTimeout', description: 'Maximum time for IMAP commands', type: 'number/string', default: '10s', group: 'General' },
    { name: '--service.setupDelay', description: 'Delay between worker connection assignments', type: 'number/string', default: '0ms', group: 'General' },
    { name: '--log.level', description: 'Logging level', type: 'string', default: 'trace', group: 'General' },
    { name: '--log.raw', description: 'Log raw IMAP traffic', type: 'boolean', default: false, group: 'General' },
    { name: '--workers.webhooks', description: 'Number of webhook worker threads', type: 'number', default: 1, group: 'General' },
    { name: '--api.host', description: 'API server bind address', type: 'string', default: '127.0.0.1', group: 'API server' },
    { name: '--api.port', description: 'API server port', type: 'number', default: 3000, group: 'API server' },
    { name: '--api.maxSize', description: 'Maximum attachment size', type: 'number/string', default: '5M', group: 'API server' },
    { name: '--queues.notify', description: 'Concurrent webhook deliveries', type: 'number', default: 1, group: 'Background tasks' },
    { name: '--queues.submit', description: 'Concurrent email submissions', type: 'number', default: 1, group: 'Background tasks' },
    { name: '--smtp.enabled', description: 'Enable SMTP submission server', type: 'boolean', default: false, group: 'SMTP server' },
    { name: '--smtp.secret', description: 'Shared SMTP password for all accounts', type: 'string', group: 'SMTP server' },
    { name: '--smtp.host', description: 'SMTP server bind address', type: 'string', default: '127.0.0.1', group: 'SMTP server' },
    { name: '--smtp.port', description: 'SMTP server port', type: 'number', default: 2525, group: 'SMTP server' },
    { name: '--smtp.proxy', description: 'Enable HAProxy PROXY protocol', type: 'boolean', default: false, group: 'SMTP server' },
    { name: '--smtp.maxMessageSize', description: 'Maximum email size', type: 'number/string', default: '25M', group: 'SMTP server' }
];

// Help formatting functions
function getTerminalWidth() {
    // Check stderr first since help outputs there, fallback to stdout, then 80
    return process.stderr.columns || process.stdout.columns || 80;
}

function wrapText(text, width, indent) {
    if (width <= 0) {
        return text;
    }
    const words = text.split(' ');
    const lines = [];
    let currentLine = '';

    for (const word of words) {
        if (currentLine.length === 0) {
            currentLine = word;
        } else if (currentLine.length + 1 + word.length <= width) {
            currentLine += ' ' + word;
        } else {
            lines.push(currentLine);
            currentLine = word;
        }
    }
    if (currentLine) {
        lines.push(currentLine);
    }

    return lines.join('\n' + ' '.repeat(indent));
}

function formatLine(name, description, type, defaultVal, width, nameWidth) {
    const indent = 2;
    const gap = 2;
    let line = ' '.repeat(indent) + name.padEnd(nameWidth);

    let descParts = [description];
    if (type) {
        descParts.push(`[${type}]`);
    }
    if (defaultVal !== undefined && defaultVal !== null) {
        descParts.push(`[default: ${defaultVal}]`);
    }

    const descText = descParts.join(' ');
    const descWidth = width - nameWidth - indent - gap;

    if (descWidth > 20) {
        line += ' '.repeat(gap) + wrapText(descText, descWidth, nameWidth + indent + gap);
    } else {
        line += ' '.repeat(gap) + descText;
    }

    return line;
}

// Calculate global name width for consistent alignment
function calculateGlobalNameWidth() {
    let maxWidth = 0;

    // Commands
    for (const cmd of Object.keys(COMMANDS)) {
        const cmdName = cmd ? `emailengine ${cmd}` : 'emailengine';
        maxWidth = Math.max(maxWidth, cmdName.length);
        if (COMMANDS[cmd].subcommands) {
            maxWidth = Math.max(maxWidth, `emailengine ${cmd} [command]`.length);
            for (const subCmd of Object.keys(COMMANDS[cmd].subcommands)) {
                maxWidth = Math.max(maxWidth, `emailengine ${cmd} ${subCmd}`.length);
                const subDef = COMMANDS[cmd].subcommands[subCmd];
                if (subDef.options) {
                    for (const opt of subDef.options) {
                        maxWidth = Math.max(maxWidth, opt.name.length);
                    }
                }
            }
        }
        if (COMMANDS[cmd].options) {
            for (const opt of COMMANDS[cmd].options) {
                maxWidth = Math.max(maxWidth, opt.name.length);
            }
        }
    }

    // Global options
    for (const opt of GLOBAL_OPTIONS) {
        maxWidth = Math.max(maxWidth, opt.name.length);
    }

    return maxWidth;
}

function generateHelp() {
    const width = getTerminalWidth();
    const nameWidth = calculateGlobalNameWidth();
    const lines = [];

    lines.push('emailengine [command] [options]');
    lines.push('');
    lines.push(wrapText(
        'EmailEngine is the self-hosted service that allows you to access any email account using an easy-to-use REST API.',
        width,
        0
    ));
    lines.push('');
    lines.push('Commands:');

    // Output commands
    for (const [cmd, def] of Object.entries(COMMANDS)) {
        const cmdName = cmd ? `emailengine ${cmd}` : 'emailengine';
        lines.push(formatLine(cmdName, def.description, null, null, width, nameWidth));
        if (def.subcommands) {
            lines.push(formatLine(
                `emailengine ${cmd} [command]`,
                `${cmd.charAt(0).toUpperCase() + cmd.slice(1)} management`,
                null,
                null,
                width,
                nameWidth
            ));
        }
    }

    // Output global options by group
    lines.push('');
    lines.push('Options:');

    let currentGroup = null;
    for (const opt of GLOBAL_OPTIONS) {
        if (opt.group && opt.group !== currentGroup) {
            currentGroup = opt.group;
            lines.push('');
            lines.push('  ' + currentGroup + ':');
        }
        lines.push(formatLine(opt.name, opt.description, opt.type, opt.default, width, nameWidth));
    }

    // Output subcommand details
    for (const [cmd, def] of Object.entries(COMMANDS)) {
        if (def.subcommands) {
            lines.push('');
            lines.push(`${cmd.charAt(0).toUpperCase() + cmd.slice(1)} management commands:`);
            for (const [subCmd, subDef] of Object.entries(def.subcommands)) {
                lines.push(formatLine(`emailengine ${cmd} ${subCmd}`, subDef.description, null, null, width, nameWidth));
                if (subDef.options) {
                    for (const opt of subDef.options) {
                        lines.push(formatLine(opt.name, opt.description, opt.type, opt.default, width, nameWidth));
                    }
                }
            }
        } else if (def.options) {
            lines.push('');
            lines.push(`${cmd.charAt(0).toUpperCase() + cmd.slice(1).replace(/-/g, ' ')} options:`);
            lines.push(formatLine(`emailengine ${cmd}`, def.description, null, null, width, nameWidth));
            for (const opt of def.options) {
                lines.push(formatLine(opt.name, opt.description, opt.type, opt.default, width, nameWidth));
            }
            if (def.example) {
                lines.push('');
                lines.push('  Example: ' + def.example);
            }
        }
    }

    return lines.join('\n');
}

function generateCommandHelp(cmdName) {
    const width = getTerminalWidth();
    const nameWidth = calculateGlobalNameWidth();
    const lines = [];

    // Check if command exists
    if (!COMMANDS[cmdName]) {
        return null;
    }

    const def = COMMANDS[cmdName];

    lines.push(`emailengine ${cmdName} [options]`);
    lines.push('');
    lines.push(wrapText(def.description, width, 0));

    if (def.subcommands) {
        lines.push('');
        lines.push('Commands:');
        for (const [subCmd, subDef] of Object.entries(def.subcommands)) {
            lines.push(formatLine(`emailengine ${cmdName} ${subCmd}`, subDef.description, null, null, width, nameWidth));
            if (subDef.options) {
                lines.push('');
                lines.push('  Options:');
                for (const opt of subDef.options) {
                    lines.push(formatLine(opt.name, opt.description, opt.type, opt.default, width, nameWidth));
                }
            }
        }
    } else if (def.options) {
        lines.push('');
        lines.push('Options:');
        for (const opt of def.options) {
            lines.push(formatLine(opt.name, opt.description, opt.type, opt.default, width, nameWidth));
        }
    }

    if (def.example) {
        lines.push('');
        lines.push('Example:');
        lines.push('  ' + def.example);
    }

    return lines.join('\n');
}

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
            {
                // Show help for specific command or general help
                let helpCmd = ((argv._ && argv._[1]) || '').toLowerCase();
                if (helpCmd) {
                    let cmdHelp = generateCommandHelp(helpCmd);
                    if (cmdHelp) {
                        console.error(cmdHelp);
                    } else {
                        console.error(`Unknown command: ${helpCmd}`);
                        console.error('');
                        console.error('Run "emailengine help" to see available commands.');
                        process.exit(1);
                    }
                } else {
                    console.error(generateHelp());
                }
                process.exit();
            }
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

        case 'export':
            {
                getSecret()
                    .then(secret => {
                        let account = (argv.account || argv.a || '').toString();
                        let accountObject = new Account({
                            redis,
                            account,
                            secret
                        });
                        return accountObject.loadAccountData(account, false);
                    })
                    .then(accountData => {
                        process.stdout.write(JSON.stringify(accountData));
                        process.exit(0);
                    })
                    .catch(err => {
                        console.error(err);
                        process.exit(1);
                    });
            }
            break;

        case 'check-bounce':
            {
                process.title = 'emailengine-check-bounce';
                const { bounceDetect } = require('../lib/bounce-detect');
                const bounceClassifier = require('@postalsys/bounce-classifier');

                let emlPath = argv._[1] || argv.file || argv.f;

                if (!emlPath) {
                    console.error('Error: EML file path is required');
                    console.error('Usage: emailengine check-bounce <path-to-eml-file>');
                    console.error('       emailengine check-bounce --file <path-to-eml-file>');
                    return process.exit(1);
                }

                // Resolve the path
                emlPath = pathlib.resolve(emlPath);

                // Check if file exists
                if (!fs.existsSync(emlPath)) {
                    console.error(`Error: File not found: ${emlPath}`);
                    return process.exit(1);
                }

                const checkBounce = async () => {
                    // Initialize the bounce classifier
                    await bounceClassifier.initialize();

                    // Read the EML file
                    const emlStream = fs.createReadStream(emlPath);

                    // Detect bounce information
                    const bounce = await bounceDetect(emlStream);

                    // Classify the bounce if we have a response message
                    if (bounce?.response?.message) {
                        const classification = await bounceClassifier.classify(bounce.response.message);

                        if (classification?.label) {
                            bounce.response.category = classification.label;
                        }
                        if (classification?.action) {
                            bounce.response.recommendedAction = classification.action;
                        }
                        if (classification?.blocklist) {
                            bounce.response.blocklist = classification.blocklist;
                        }
                        if (classification?.retryAfter) {
                            bounce.response.retryAfter = classification.retryAfter;
                        }
                    }

                    return bounce;
                };

                checkBounce()
                    .then(result => {
                        process.stdout.write(JSON.stringify(result, null, 2));
                        process.stdout.write('\n');
                        return process.exit(0);
                    })
                    .catch(err => {
                        console.error('Failed to analyze bounce email');
                        console.error(err);
                        return process.exit(1);
                    });
            }
            break;

        default:
            // run normally
            require('../server');
            break;
    }
}

run();
