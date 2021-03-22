'use strict';

const { parentPort } = require('worker_threads');
const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');
const Joi = require('joi');
const logger = require('../lib/logger');
const hapiPino = require('hapi-pino');
const { ImapFlow } = require('imapflow');
const nodemailer = require('nodemailer');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');
const packageData = require('../package.json');
const pathlib = require('path');
const config = require('wild-config');
const { PassThrough } = require('stream');
const msgpack = require('msgpack5')();
const consts = require('../lib/consts');

const { redis } = require('../lib/db');
const { Account } = require('../lib/account');
const settings = require('../lib/settings');
const { getByteSize } = require('../lib/tools');

const RESYNC_DELAY = 15 * 60;
const DEFAULT_MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024;

config.api = config.api || {
    port: 3000,
    host: '127.0.0.1'
};

const MAX_ATTACHMENT_SIZE = getByteSize(process.env.API_MAX_SIZE || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;

// allowed configuration keys
const settingsSchema = {
    webhooks: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .example('https://myservice.com/imap/webhooks')
        .description('Webhook URL'),

    webhookEvents: Joi.array().items(Joi.string().max(256)),

    notifyHeaders: Joi.array().items(Joi.string().max(256)),

    authServer: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://myservice.com/authentication')
        .description('URL to fetch authentication data from')
        .label('AuthServer'),

    notifyText: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Include message text in webhook notification'),

    notifyTextSize: Joi.number().min(0),

    logs: Joi.object({
        all: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Enable logs for all accounts'),
        resetLoggedAccounts: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Reconnect logged accounts'),
        accounts: Joi.array()
            .items(Joi.string().max(256))
            .default([])
            .example(['account-id-1', 'account-id-2'])
            .description('Enable logs for listed accounts')
            .label('LoggedAccounts'),
        maxLogLines: Joi.number().min(0).max(1000000).default(10000)
    }).label('LogSettings')
};

const addressSchema = Joi.object({
    name: Joi.string().max(256).example('Some Name'),
    address: Joi.string()
        .email({
            ignoreLength: false
        })
        .example('user@example.com')
        .required()
}).label('Address');

// generate a list of boolean values
const settingsQuerySchema = Object.fromEntries(
    Object.keys(Object.assign({ eventTypes: true }, settingsSchema)).map(key => [
        key,
        Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false)
    ])
);

const imapSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username'),
        pass: Joi.string().max(256).example('verysecret').description('Account password'),
        accessToken: Joi.string().max(4096).description('Access Token for OAuth2')
    })
        .xor('pass', 'accessToken')
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .min(1)
        .max(64 * 1024)
        .required()
        .example(993)
        .description('Service port number'),
    secure: Joi.boolean().default(false).example(true).description('Should connection use TLS. Usually true for port 993'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .description('Optional TLS configuration')
        .label('TLS'),
    resyncDelay: Joi.number().example(RESYNC_DELAY).description('Full resync delay in seconds').default(RESYNC_DELAY)
};

const smtpSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username'),
        pass: Joi.string().max(256).example('verysecret').description('Account password'),
        accessToken: Joi.string().max(4096).description('Access Token for OAuth2')
    })
        .xor('pass', 'accessToken')
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .min(1)
        .max(64 * 1024)
        .required()
        .example(587)
        .description('Service port number'),
    secure: Joi.boolean().default(false).example(false).description('Should connection use TLS. Usually true for port 465'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .description('Optional TLS configuration')
        .label('TLS')
};

const failAction = async (request, h, err) => {
    let details = (err.details || []).map(detail => ({ message: detail.message, key: detail.context.key }));

    logger.error({
        msg: 'Request failed',
        method: request.method,
        route: request.route.path,
        statusCode: request.response && request.response.statusCode,
        err
    });

    let error = Boom.boomify(new Error('Invalid input'), { statusCode: 400 });
    error.reformat();
    error.output.payload.fields = details; // Add custom key
    throw error;
};

let callQueue = new Map();
let mids = 0;

async function call(message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response');
            err.statusCode = 504;
            err.code = 'Timeout';
            reject(err);
        }, message.timeout || 10 * 1000);

        callQueue.set(mid, { resolve, reject, timer });

        parentPort.postMessage(
            {
                cmd: 'call',
                mid,
                message
            },
            transferList
        );
    });
}

async function metrics(key, method, ...args) {
    parentPort.postMessage({
        cmd: 'metrics',
        key,
        method,
        args
    });
}

async function notify(cmd, data) {
    parentPort.postMessage({
        cmd,
        data
    });
}

async function onCommand(command) {
    logger.debug({ msg: 'Unhandled command', command });
}

parentPort.on('message', message => {
    if (message && message.cmd === 'resp' && message.mid && callQueue.has(message.mid)) {
        let { resolve, reject, timer } = callQueue.get(message.mid);
        clearTimeout(timer);
        callQueue.delete(message.mid);
        if (message.error) {
            let err = new Error(message.error);
            if (message.code) {
                err.code = message.code;
            }
            if (message.statusCode) {
                err.statusCode = message.statusCode;
            }
            return reject(err);
        } else {
            return resolve(message.response);
        }
    }

    if (message && message.cmd === 'call' && message.mid) {
        return onCommand(message.message)
            .then(response => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    response
                });
            })
            .catch(err => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    error: err.message,
                    code: err.code,
                    statusCode: err.statusCode
                });
            });
    }
});

const init = async () => {
    const server = Hapi.server({
        port: (process.env.API_PORT && Number(process.env.API_PORT)) || config.api.port,
        host: process.env.API_HOST || config.api.host
    });

    const swaggerOptions = {
        swaggerUI: true,
        swaggerUIPath: '/swagger/',
        documentationPage: true,
        documentationPath: '/docs',

        grouping: 'tags',

        info: {
            title: 'IMAP API',
            version: packageData.version,
            contact: {
                name: 'Andris Reinman',
                email: 'andris@imapapi.com'
            }
        }
    };

    await server.register({
        plugin: hapiPino,
        options: {
            instance: logger.child({ component: 'api' }),
            // Redact Authorization headers, see https://getpino.io/#/docs/redaction
            redact: ['req.headers.authorization']
        }
    });

    await server.register([
        Inert,
        Vision,
        {
            plugin: HapiSwagger,
            options: swaggerOptions
        }
    ]);

    server.events.on('response', request => {
        if (!/^\/v1\//.test(request.route.path)) {
            // only log API calls
            return;
        }
        metrics('apiCall', 'inc', {
            method: request.method,
            route: request.route.path,
            statusCode: request.response && request.response.statusCode
        });
    });

    server.route({
        method: 'GET',
        path: '/',
        handler: {
            file: pathlib.join(__dirname, '..', 'static', 'index.html')
        }
    });

    server.route({
        method: 'GET',
        path: '/favicon.ico',
        handler: {
            file: pathlib.join(__dirname, '..', 'static', 'favicon.ico')
        }
    });

    server.route({
        method: 'GET',
        path: '/static/{file*}',
        handler: {
            directory: {
                path: pathlib.join(__dirname, '..', 'static')
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account',

        async handler(request) {
            let accountObject = new Account({ redis, call });

            try {
                let result = await accountObject.create(request.payload);
                return result;
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Register new account',
            notes: 'Registers new IMAP account to be synced',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),

                    name: Joi.string().max(256).required().example('My Email Account').description('Display name for the account'),

                    copy: Joi.boolean().example(true).description('Copy submitted messages to Sent folder').default(true),
                    notifyFrom: Joi.date().example('2020-01-01').description('Notify messages from date').default('now').iso(),

                    imap: Joi.object(imapSchema).xor('useAuthServer', 'auth').description('IMAP configuration').label('IMAP'),

                    smtp: Joi.object(smtpSchema).allow(false).xor('useAuthServer', 'auth').description('SMTP configuration').label('SMTP')
                }).label('CreateAccount')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    state: Joi.string().required().valid('existing', 'new').example('new').description('Is the account new or updated existing')
                }).label('CreateAccountReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.update(request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Update account info',
            notes: 'Updates account information',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),

                    copy: Joi.boolean().example(true).description('Copy submitted messages to Sent folder').default(true),
                    notifyFrom: Joi.date().example('2020-01-01').description('Notify messages from date').default('now').iso(),

                    imap: Joi.object(imapSchema).xor('useAuthServer', 'auth').description('IMAP configuration').label('IMAP'),
                    smtp: Joi.object(smtpSchema).allow(false).xor('useAuthServer', 'auth').description('SMTP configuration').label('SMTP')
                }).label('UpdateAccount')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }).label('UpdateAccountReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/reconnect',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return { reconnect: await accountObject.requestReconnect(request.payload) };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Request reconnect',
            notes: 'Requests connection to be reconnected',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    reconnect: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only reconnect if true')
                }).label('RequestReconnect')
            },

            response: {
                schema: Joi.object({
                    reconnect: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Only reconnect if true')
                }).label('RequestReconnectReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.delete();
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Remove synced account',
            notes: 'Stop syncing IMAP account and delete cached values',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }).label('DeleteRequest')
            },

            response: {
                schema: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the account deleted')
                }).label('DeleteRequestReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/accounts',

        async handler(request) {
            try {
                let accounts = await redis.smembers('ia:accounts');
                let getStates = redis.pipeline();
                for (let account of accounts) {
                    getStates = getStates.hgetall(`iad:${account}`);
                }

                let results = await getStates.exec();
                let accountList = results
                    .map(
                        row =>
                            row &&
                            row[1] && {
                                account: row[1].account,
                                name: row[1].name,
                                state: row[1].state,
                                syncTime: row[1].sync,
                                lastError: row[1].state === 'connected' ? null : parseJSON(row[1].lastErrorState)
                            }
                    )
                    .filter(row => row)
                    .filter(row => !request.query.state || request.query.state === row.state)
                    .sort((a, b) => a.account.toLowerCase().localeCompare(b.account.toLowerCase()));

                return { accounts: accountList };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },

        options: {
            description: 'List accounts',
            notes: 'Lists registered accounts',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    state: Joi.string()
                        .valid('init', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                        .example('connected')
                        .description('Filter accounts by state')
                        .label('AccountState')
                }).label('AccountsFilter')
            },

            response: {
                schema: Joi.object({
                    accounts: Joi.array().items(
                        Joi.object({
                            account: Joi.string().max(256).required().example('example').description('Account ID'),
                            name: Joi.string().max(256).example('My Email Account').description('Display name for the account'),
                            state: Joi.string()
                                .required()
                                .valid('init', 'connecting', 'connected', 'authenticationError', 'connectError', 'unset', 'disconnected')
                                .example('connected')
                                .description('Account state'),
                            syncTime: Joi.date().example('2021-02-17T13:43:18.860Z').description('Last sync time').iso(),
                            lastError: Joi.object({
                                response: Joi.string().example('Request to authentication server failed'),
                                serverResponseCode: Joi.string().example('HTTPRequestError')
                            })
                                .allow(null)
                                .label('AccountErrorEntry')
                        }).label('AccountResponseItem')
                    )
                }).label('AccountsFilterReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/mailboxes',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return { mailboxes: await accountObject.getMailboxListing() };
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },

        options: {
            description: 'List mailboxes',
            notes: 'Lists all available mailboxes',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            },

            response: {
                schema: Joi.object({
                    mailboxes: Joi.array().items(
                        Joi.object({
                            path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                            parentPath: Joi.string().required().example('Kalender').description('Full path to parent mailbox').label('MailboxParentPath'),
                            name: Joi.string().required().example('Sünnipäevad').description('Maibox name').label('MailboxName'),
                            listed: Joi.boolean().example(true).description('Was the mailbox found from the output of LIST command').label('MailboxListed'),
                            subscribed: Joi.boolean()
                                .example(true)
                                .description('Was the mailbox found from the output of LSUB command')
                                .label('MailboxSubscribed'),
                            specialUse: Joi.string()
                                .example('\\Sent')
                                .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
                                .description('Special use flag of the mailbox if set')
                                .label('MailboxSpecialUse'),
                            messages: Joi.number().example(120).description('Count of messages in mailbox').label('MailboxMessages'),
                            uidNext: Joi.number().example(121).description('Next expected UID').label('MailboxMUidNext')
                        }).label('MailboxResponseItem')
                    )
                }).label('MailboxesFilterReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.createMailbox(request.payload.path);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },

        options: {
            description: 'Create mailbox',
            notes: 'Create new mailbox folder',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).example('example').required().description('Account ID')
                }),

                payload: Joi.object({
                    path: Joi.array()
                        .items(Joi.string().max(256))
                        .example(['Parent folder', 'Subfolder'])
                        .description('Mailbox path as an array. If account is namespaced then namespace prefix is added by default.')
                        .label('MailboxPath')
                }).label('CreateMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                    mailboxId: Joi.string().example('1439876283476').description('Mailbox ID (if server has support)').label('MailboxId'),
                    created: Joi.boolean().example(true).description('Was the mailbox created')
                }).label('CreateMailboxReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.deleteMailbox(request.query.path);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },

        options: {
            description: 'Delete mailbox',
            notes: 'Delete existing mailbox folder',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('My Outdated Mail').description('Mailbox folder path to delete').label('MailboxPath')
                }).label('DeleteMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                    deleted: Joi.boolean().example(true).description('Was the mailbox deleted')
                }).label('DeleteMailboxReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/message/{message}/source',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.getRawMessage(request.params.message);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Download raw message',
            notes: 'Fetches raw message as a stream',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().base64({ paddingRequired: false, urlSafe: true }).max(256).example('AAAAAQAACnA').required().description('Message ID')
                }).label('RawMessageRequest')
            } /*,

            response: {
                schema: Joi.binary().example('MIME-Version: 1.0...').description('RFC822 formatted email').label('RawMessageResponse'),
                failAction: 'log'
            }
            */
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/attachment/{attachment}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.getAttachment(request.params.attachment);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Download attachment',
            notes: 'Fetches attachment file as a stream',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    attachment: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(256)
                        .required()
                        .example('AAAAAQAACnAcde')
                        .description('Attachment ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.getMessage(request.params.message, request.query);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Get message information',
            notes: 'Returns details of a specific message. By default text content is not included, use textType value to force retrieving text',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    maxBytes: Joi.number()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(5 * 1025 * 1024)
                        .description('Max length of text content'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default text content is not returned.')
                }),

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().base64({ paddingRequired: false, urlSafe: true }).max(256).required().example('AAAAAQAACnA').description('Message ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/message',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.uploadMessage(request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            payload: {
                // allow message uploads up to 50MB
                // TODO: should it be configurable instead?
                maxBytes: 50 * 1024 * 1024
            },

            description: 'Upload message to a folder',
            notes: 'Upload a message structure, compile it into an EML file and store it into selected mailbox.',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),

                    flags: Joi.array().items(Joi.string().max(128)).example(['\\Seen', '\\Draft']).default([]).description('Message flags').label('Flags'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        action: Joi.string().lowercase().valid('forward', 'reply').example('reply').default('reply')
                    })
                        .description('Message reference for a reply or a forward. This is IMAP API specific ID, not Message-ID header value.')
                        .label('MessageReference'),

                    from: addressSchema.required().example({ name: 'From Me', address: 'sender@example.com' }),

                    to: Joi.array()
                        .items(addressSchema)
                        .description('List of addresses')
                        .example([{ address: 'recipient@example.com' }])
                        .label('AddressList'),

                    cc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

                    bcc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

                    subject: Joi.string().max(1024).example('What a wonderful message').description('Message subject'),

                    text: Joi.string().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Message Text'),

                    html: Joi.string().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('Message HTML'),

                    attachments: Joi.array()
                        .items(
                            Joi.object({
                                filename: Joi.string().max(256).example('transparent.gif'),
                                content: Joi.string()
                                    .base64()
                                    .max(MAX_ATTACHMENT_SIZE)
                                    .required()
                                    .example('R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=')
                                    .description('Base64 formatted attachment file'),
                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64')
                            }).label('Attachment')
                        )
                        .description('List of attachments')
                        .label('AttachmentList'),

                    messageId: Joi.string().max(74).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().description('Custom Headers')
                }).label('MessageUpload')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string()
                        .example('AAAAAgAACrI')
                        .description('Message ID. NB! This and other fields might not be present if server did not provide enough information')
                        .label('MessageAppendId'),
                    path: Joi.string().example('INBOX').description('Folder this message was uploaded to').label('MessageAppendPath'),
                    uid: Joi.number().example(12345).description('UID of uploaded message'),
                    seq: Joi.number().example(12345).description('Sequence number of uploaded message')
                }).label('MessageUploadResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.updateMessage(request.params.message, request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Update message',
            notes: 'Update message information. Mainly this means changing message flag values',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: Joi.object({
                    flags: Joi.object({
                        add: Joi.array().items(Joi.string().max(128)).description('Add new flags').example(['\\Seen']).label('AddFlags'),
                        delete: Joi.array().items(Joi.string().max(128)).description('Delete specific flags').example(['\\Flagged']).label('DeleteFlags'),
                        set: Joi.array().items(Joi.string().max(128)).description('Override all flags').example(['\\Seen', '\\Flagged']).label('SetFlags')
                    })
                        .description('Flag updates')
                        .label('FlagUpdate'),

                    labels: Joi.object({
                        add: Joi.array().items(Joi.string().max(128)).description('Add new labels').example(['Some label']).label('AddLabels'),
                        delete: Joi.array().items(Joi.string().max(128)).description('Delete specific labels').example(['Some label']).label('DeleteLabels'),
                        set: Joi.array()
                            .items(Joi.string().max(128))
                            .description('Override all labels')
                            .example(['First label', 'Second label'])
                            .label('SetLabels')
                    })
                        .description('Label updates')
                        .label('LabelUpdate')
                }).label('MessageUpdate')
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/message/{message}/move',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.moveMessage(request.params.message, request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Move message',
            notes: 'Move message to another folder',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path')
                }).label('MessageMove')
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.deleteMessage(request.params.message);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Delete message',
            notes: 'Move message to Trash or delete it if already in Trash',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/text/{text}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.getText(request.params.text, request.query);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Retrieve message text',
            notes: 'Retrieves message text',
            tags: ['api', 'message'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object({
                    maxBytes: Joi.number()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(MAX_ATTACHMENT_SIZE)
                        .description('Max length of text content'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .default('*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default all contents are returned.')
                }),

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID'),
                    text: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(256)
                        .required()
                        .example('AAAAAQAACnAcdfaaN')
                        .description('Message text ID')
                }).label('Text')
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/messages',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });
            try {
                return await accountObject.listMessages(request.query);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'List messages in a folder',
            notes: 'Lists messages in a mailbox folder',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID').label('AccountId')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Mailbox folder path').label('Path'),
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('MessageQuery')
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/search',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });
            try {
                return await accountObject.listMessages(Object.assign(request.query, request.payload));
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Search for messages in a folder',
            notes: 'Filter messages from a mailbox folder by search options',
            tags: ['api', 'mailbox'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Mailbox folder path'),
                    page: Joi.number()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)'),
                    pageSize: Joi.number().min(1).max(1000).default(20).example(20).description('How many entries per page')
                }),

                payload: Joi.object({
                    search: Joi.object({
                        seq: Joi.string().max(256).description('Sequence number range'),

                        answered: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is answered or not')
                            .label('AnsweredFlag'),
                        deleted: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked for being deleted or not')
                            .label('DeletedFlag'),
                        draft: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('Check if message is a draft').label('DraftFlag'),
                        unseen: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked as unseen or not')
                            .label('UnseenFlag'),
                        flagged: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is flagged or not')
                            .label('Flagged'),
                        seen: Joi.boolean()
                            .truthy('Y', 'true', '1')
                            .falsy('N', 'false', 0)
                            .description('Check if message is marked as seen or not')
                            .label('SeenFlag'),

                        from: Joi.string().max(256).description('Match From: header').label('From'),
                        to: Joi.string().max(256).description('Match To: header').label('To'),
                        cc: Joi.string().max(256).description('Match Cc: header').label('Cc'),
                        bcc: Joi.string().max(256).description('Match Bcc: header').label('Bcc'),

                        body: Joi.string().max(256).description('Match text body').label('MessageBody'),
                        subject: Joi.string().max(256).description('Match message subject').label('Subject'),

                        larger: Joi.number()
                            .min(0)
                            .max(1024 * 1024 * 1024)
                            .description('Matches messages larger than value')
                            .label('MessageLarger'),

                        smaller: Joi.number()
                            .min(0)
                            .max(1024 * 1024 * 1024)
                            .description('Matches messages smaller than value')
                            .label('MessageSmaller'),

                        uid: Joi.string().max(256).description('UID range').label('UIDRange'),

                        modseq: Joi.number().min(0).description('Matches messages with modseq higher than value').label('ModseqLarger'),

                        before: Joi.date().description('Matches messages received before date').label('EnvelopeBefore'),
                        since: Joi.date().description('Matches messages received after date').label('EnvelopeSince'),

                        sentBefore: Joi.date().description('Matches messages sent before date').label('HeaderBefore'),
                        sentSince: Joi.date().description('Matches messages sent after date').label('HeaderSince'),

                        emailId: Joi.string().max(256).description('Match specific Gmail unique email UD'),
                        threadId: Joi.string().max(256).description('Match specific Gmail unique thread UD'),

                        header: Joi.object().unknown(true).description('Headers to match against').label('Headers')
                    })
                        .required()
                        .description('Search query to filter messages')
                        .label('SearchQuery')
                }).label('SearchQuery')
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/contacts',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });
            try {
                return await accountObject.buildContacts();
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Builds a contact listing',
            notes: 'Builds a contact listings from email addresses. For larger mailboxes this could take a lot of time.',
            tags: [/*'api', */ 'experimental'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/submit',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call });

            try {
                return await accountObject.submitMessage(request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            payload: {
                // allow message uploads up to 50MB
                // TODO: should it be configurable instead?
                maxBytes: 50 * 1024 * 1024
            },

            description: 'Submit message for delivery',
            notes:
                'Submit message for delivery. If reference message ID is provided then IMAP API adds all headers and flags required for a reply/forward automatically.',
            tags: ['api', 'submit'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                }),

                payload: Joi.object({
                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        action: Joi.string().lowercase().valid('forward', 'reply').example('reply').default('reply')
                    })
                        .description('Message reference for a reply or a forward. This is IMAP API specific ID, not Message-ID header value.')
                        .label('MessageReference'),

                    from: addressSchema.required().example({ name: 'From Me', address: 'sender@example.com' }),

                    to: Joi.array()
                        .items(addressSchema)
                        .description('List of addresses')
                        .example([{ address: 'recipient@example.com' }])
                        .label('AddressList'),

                    cc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

                    bcc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

                    subject: Joi.string().max(1024).example('What a wonderful message').description('Message subject'),

                    text: Joi.string().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Message Text'),

                    html: Joi.string().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('Message HTML'),

                    attachments: Joi.array()
                        .items(
                            Joi.object({
                                filename: Joi.string().max(256).example('transparent.gif'),
                                content: Joi.string()
                                    .base64()
                                    .max(MAX_ATTACHMENT_SIZE)
                                    .required()
                                    .example('R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=')
                                    .description('Base64 formatted attachment file'),
                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64')
                            }).label('Attachment')
                        )
                        .description('List of attachments')
                        .label('AttachmentList'),

                    messageId: Joi.string().max(74).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().description('Custom Headers')
                }).label('Message')
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/settings',

        async handler(request) {
            let values = {};
            for (let key of Object.keys(request.query)) {
                if (request.query[key]) {
                    if (key === 'eventTypes') {
                        values[key] = Object.keys(consts)
                            .map(key => {
                                if (/_NOTIFY?/.test(key)) {
                                    return consts[key];
                                }
                                return false;
                            })
                            .map(key => key);
                        continue;
                    }

                    let value = await settings.get(key);
                    values[key] = value;
                }
            }
            return values;
        },
        options: {
            description: 'List specific settings',
            notes: 'List setting values for specific keys',
            tags: ['api', 'settings'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                query: Joi.object(settingsQuerySchema).label('SettingsQuery')
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/settings',

        async handler(request) {
            let updated = [];
            for (let key of Object.keys(request.payload)) {
                switch (key) {
                    case 'logs': {
                        let logs = request.payload.logs;
                        let resetLoggedAccounts = logs.resetLoggedAccounts;
                        delete logs.resetLoggedAccounts;
                        if (resetLoggedAccounts && logs.accounts && logs.accounts.length) {
                            for (let account of logs.accounts) {
                                logger.info({ msg: 'Request reconnect for logging', account });
                                try {
                                    await call({ cmd: 'update', account });
                                } catch (err) {
                                    logger.error({ action: 'request_reconnect', account, err });
                                }
                            }
                        }
                    }
                }

                await settings.set(key, request.payload[key]);
                updated.push(key);
            }

            notify('settings', request.payload);
            return { updated };
        },
        options: {
            description: 'Set setting values',
            notes: 'Set setting values for specific keys',
            tags: ['api', 'settings'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object(settingsSchema).label('Settings')
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/logs/{account}',

        async handler(request) {
            return getLogs(request.params.account);
        },
        options: {
            description: 'Return IMAP logs for an account. Output is a downloadable text file.',
            tags: ['api', 'logs'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: Joi.string().max(256).required().example('example').description('Account ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/stats',

        async handler() {
            return await getStats();
        },
        options: {
            description: 'Return server stats',
            tags: ['api', 'stats']
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/verifyAccount',

        async handler(request) {
            try {
                return await verifyAccountInfo(request.payload);
            } catch (err) {
                if (Boom.isBoom(err)) {
                    throw err;
                }
                throw Boom.boomify(err, { statusCode: err.statusCode || 500, decorate: { code: err.code } });
            }
        },
        options: {
            description: 'Verify IMAP and SMTP settings',
            notes: 'Checks if can connect and authenticate using provided account info',
            tags: ['api', 'account'],

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                payload: Joi.object({
                    imap: Joi.object(imapSchema).description('IMAP configuration').label('IMAP'),
                    smtp: Joi.object(smtpSchema).allow(false).description('SMTP configuration').label('SMTP')
                }).label('VerifyAccount')
            },
            response: {
                schema: Joi.object({
                    imap: Joi.object({
                        success: Joi.boolean().example(true).description('Was IMAP account verified').label('VerifyImapSuccess'),
                        error: Joi.string()
                            .example('Something went wrong')
                            .description('Error messages for IMAP verification. Only present if success=false')
                            .label('VerifyImapError'),
                        code: Joi.string()
                            .example('ERR_SSL_WRONG_VERSION_NUMBER')
                            .description('Error code. Only present if success=false')
                            .label('VerifyImapCode')
                    }),
                    smtp: Joi.object({
                        success: Joi.boolean().example(true).description('Was SMTP account verified').label('VerifySmtpSuccess'),
                        error: Joi.string()
                            .example('Something went wrong')
                            .description('Error messages for SMTP verification. Only present if success=false')
                            .label('VerifySmtpError'),
                        code: Joi.string()
                            .example('ERR_SSL_WRONG_VERSION_NUMBER')
                            .description('Error code. Only present if success=false')
                            .label('VerifySmtpCode')
                    })
                }).label('VerifyAccountReponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/metrics',
        async handler(request, h) {
            const renderedMetrics = await call({ cmd: 'metrics' });
            const response = h.response('success');
            response.type('text/plain');
            return renderedMetrics;
        }
    });

    server.route({
        method: '*',
        path: '/{any*}',
        async handler() {
            throw Boom.notFound('Requested page not found'); // 404
        }
    });

    await server.start();
};

function getLogs(account) {
    let logKey = `iam:${account}:g`;
    let passThrough = new PassThrough();

    redis
        .lrangeBuffer(logKey, 0, -1)
        .then(rows => {
            if (!rows || !Array.isArray(rows) || !rows.length) {
                return passThrough.end(`No logs found for ${account}\n`);
            }
            let processNext = () => {
                if (!rows.length) {
                    return passThrough.end();
                }

                let row = rows.shift();
                let entry;
                try {
                    entry = msgpack.decode(row);
                } catch (err) {
                    entry = { error: err.stack };
                }

                if (entry) {
                    if (!passThrough.write(JSON.stringify(entry) + '\n')) {
                        return passThrough.once('drain', processNext);
                    }
                }

                setImmediate(processNext);
            };

            processNext();
        })
        .catch(err => {
            passThrough.end(`\nFailed to process logs\n${err.stack}\n`);
        });

    return passThrough;
}

async function verifyAccountInfo(accountData) {
    let response = {};

    if (accountData.imap) {
        try {
            let imapClient = new ImapFlow(
                Object.assign(
                    {
                        verifyOnly: true
                    },
                    accountData.imap
                )
            );

            await new Promise((resolve, reject) => {
                imapClient.on('error', err => {
                    reject(err);
                });
                imapClient.connect().then(resolve).catch(reject);
            });

            response.imap = {
                success: !!imapClient.authenticated
            };
        } catch (err) {
            response.imap = {
                success: false,
                error: err.message,
                code: err.code,
                statusCode: err.statusCode
            };
        }
    }

    if (accountData.smtp) {
        try {
            let smtpClient = nodemailer.createTransport(Object.assign({}, accountData.smtp));
            response.smtp = {
                success: await smtpClient.verify()
            };
        } catch (err) {
            response.smtp = {
                success: false,
                error: err.message,
                code: err.code,
                statusCode: err.statusCode
            };
        }
    }

    return response;
}

function parseJSON(value) {
    if (!value || typeof value !== 'string') {
        return null;
    }

    try {
        return JSON.parse(value);
    } catch (err) {
        return { error: err.message };
    }
}

async function getStats() {
    const structuredMetrics = await call({ cmd: 'structuredMetrics' });

    let stats = Object.assign(
        {
            version: packageData.version,
            license: packageData.license,
            accounts: await redis.scard('ia:accounts')
        },
        structuredMetrics
    );

    return stats;
}

init()
    .then(() => {
        logger.debug({
            msg: 'API server started',
            port: (process.env.API_PORT && Number(process.env.API_PORT)) || config.api.port,
            host: process.env.API_HOST || config.api.host,
            maxSize: MAX_ATTACHMENT_SIZE
        });
    })
    .catch(err => {
        logger.error(err);
        setImmediate(() => process.exit(3));
    });
