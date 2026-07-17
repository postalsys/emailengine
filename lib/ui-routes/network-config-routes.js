'use strict';

// Admin UI routes for network, SMTP server, IMAP proxy, and browser config pages
// (/admin/config/{network*,imap-proxy,smtp*,browser}). Extracted verbatim from
// lib/routes-ui.js. The network page also reloads/deletes the autodetected public
// interfaces; the SMTP/IMAP-proxy pages manage the built-in MSA and IMAP proxy servers
// (including on-demand TLS certificate provisioning).

const Joi = require('joi');
const os = require('os');
const { parentPort } = require('worker_threads');

const settings = require('../settings');
const { redis } = require('../db');
const { REDIS_PREFIX } = require('../consts');
const { failAction, getServiceHostname } = require('../tools');
const { ADDRESS_STRATEGIES, settingsSchema } = require('../schemas');
const { updatePublicInterfaces } = require('../utils/network');
const { getServerStatus, cachedTemplates } = require('./route-helpers');

const configSmtpSchema = {
    smtpServerEnabled: settingsSchema.smtpServerEnabled.default(false),
    smtpServerPassword: settingsSchema.smtpServerPassword.default(null),
    smtpServerAuthEnabled: settingsSchema.smtpServerAuthEnabled.default(false),
    smtpServerPort: settingsSchema.smtpServerPort,
    smtpServerHost: settingsSchema.smtpServerHost.default('0.0.0.0'),
    smtpServerProxy: settingsSchema.smtpServerProxy.default(false),
    smtpServerTLSEnabled: settingsSchema.smtpServerTLSEnabled.default(false)
};

const configImapProxySchema = {
    imapProxyServerEnabled: settingsSchema.imapProxyServerEnabled.default(false),
    imapProxyServerPassword: settingsSchema.imapProxyServerPassword.default(null),
    imapProxyServerPort: settingsSchema.imapProxyServerPort,
    imapProxyServerHost: settingsSchema.imapProxyServerHost.default('0.0.0.0'),
    imapProxyServerProxy: settingsSchema.imapProxyServerProxy.default(false),
    imapProxyServerTLSEnabled: settingsSchema.imapProxyServerTLSEnabled.default(false)
};

async function listPublicInterfaces(selectedAddresses) {
    let existingAddresses = Object.values(os.networkInterfaces())
        .flatMap(entry => entry)
        .map(entry => entry.address);

    let entries = await redis.hgetall(`${REDIS_PREFIX}interfaces`);

    let defaultInterfaces = {};

    let addresses = Object.keys(entries)
        .map(key => {
            if (/^default:/.test(key)) {
                let family = key.split(':').pop();
                defaultInterfaces[family] = entries[key];
                return false;
            }

            let entry = entries[key];
            try {
                return JSON.parse(entry);
            } catch (err) {
                return false;
            }
        })
        .filter(entry => entry && entry.family === 'IPv4')
        .map(entry => entry);

    addresses.forEach(address => {
        if (address.localAddress === defaultInterfaces[address.family]) {
            address.defaultInterface = true;
        }

        if (selectedAddresses && selectedAddresses.includes(address.localAddress)) {
            address.checked = true;
        }

        if (!existingAddresses.includes(address.localAddress)) {
            address.notice = 'This address was not found from the current interface listing and will not be used for connections';
        }
    });

    return addresses.sort((a, b) => {
        if (a.family !== b.family) {
            return a.family.localeCompare(b.family);
        }
        if (a.defaultInterface) {
            return -1;
        }
        if (b.defaultInterface) {
            return 1;
        }
        return (a.name || a.ip).localeCompare(b.name || b.ip);
    });
}

function init(args) {
    const { server, call } = args;

    server.route({
        method: 'GET',
        path: '/admin/config/network',
        async handler(request, h) {
            let smtpStrategy = (await settings.get('smtpStrategy')) || 'default';
            let imapStrategy = (await settings.get('imapStrategy')) || 'default';

            let proxyEnabled = await settings.get('proxyEnabled');
            let proxyUrl = await settings.get('proxyUrl');
            let smtpEhloName = await settings.get('smtpEhloName');
            let httpProxyEnabled = await settings.get('httpProxyEnabled');
            let httpProxyUrl = await settings.get('httpProxyUrl');

            let localAddresses = [].concat((await settings.get('localAddresses')) || []);

            let smtpStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: smtpStrategy === entry.key }, entry));
            let imapStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: imapStrategy === entry.key }, entry));

            return h.view(
                'config/network',
                {
                    pageTitle: 'Network',
                    menuConfig: true,
                    menuConfigNetwork: true,

                    smtpStrategies,
                    imapStrategies,

                    values: {
                        proxyEnabled,
                        proxyUrl,
                        smtpEhloName,
                        httpProxyEnabled,
                        httpProxyUrl
                    },

                    addresses: await listPublicInterfaces(localAddresses),
                    addressListTemplate: cachedTemplates.addressList,
                    defaultSmtpEhloName: await getServiceHostname()
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/network/reload',
        async handler(request) {
            try {
                await updatePublicInterfaces(redis);

                let localAddresses = [].concat((await settings.get('localAddresses')) || []);

                return {
                    success: true,
                    addresses: await listPublicInterfaces(localAddresses)
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed loading public IP addresses', err });
                return {
                    success: false,
                    error: err.message
                };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/network',
        async handler(request, h) {
            try {
                for (let key of [
                    'smtpStrategy',
                    'imapStrategy',
                    'localAddresses',
                    'proxyUrl',
                    'smtpEhloName',
                    'proxyEnabled',
                    'httpProxyEnabled',
                    'httpProxyUrl'
                ]) {
                    await settings.set(key, request.payload[key]);
                }

                // Notify all workers (including this one) about the settings change; each reloads
                // its HTTP proxy agent via the 'settings' message handler.
                if (parentPort) {
                    parentPort.postMessage({ cmd: 'settings', data: request.payload });
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/network');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let smtpStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: request.payload.smtpStrategy === entry.key }, entry));
                let imapStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: request.payload.imapStrategy === entry.key }, entry));

                return h.view(
                    'config/network',
                    {
                        pageTitle: 'Network',
                        menuConfig: true,
                        menuConfigNetwork: true,
                        smtpStrategies,
                        imapStrategies,

                        addresses: await listPublicInterfaces(request.payload.localAddresses),
                        addressListTemplate: cachedTemplates.addressList,
                        defaultSmtpEhloName: await getServiceHostname()
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let smtpStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: request.payload.smtpStrategy === entry.key }, entry));
                    let imapStrategies = ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: request.payload.imapStrategy === entry.key }, entry));

                    return h
                        .view(
                            'config/network',
                            {
                                pageTitle: 'Network',
                                menuConfig: true,
                                menuConfigNetwork: true,
                                smtpStrategies,
                                imapStrategies,

                                addresses: await listPublicInterfaces(request.payload.localAddresses),
                                addressListTemplate: cachedTemplates.addressList,
                                defaultSmtpEhloName: await getServiceHostname(),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },
                payload: Joi.object({
                    imapStrategy: settingsSchema.imapStrategy.default('default'),
                    smtpStrategy: settingsSchema.smtpStrategy.default('default'),
                    localAddresses: settingsSchema.localAddresses.default([]),

                    proxyUrl: settingsSchema.proxyUrl,
                    smtpEhloName: settingsSchema.smtpEhloName,
                    proxyEnabled: settingsSchema.proxyEnabled,

                    httpProxyEnabled: settingsSchema.httpProxyEnabled,
                    httpProxyUrl: settingsSchema.httpProxyUrl
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/network/delete',
        async handler(request, h) {
            try {
                let localAddress = request.payload.localAddress;
                let localAddresses = [].concat((await settings.get('localAddresses')) || []);
                if (localAddresses.includes(localAddress)) {
                    let list = new Set(localAddresses);
                    list.delete(localAddress);
                    localAddresses = Array.from(list);
                    await settings.set('localAddresses', localAddresses);
                }

                await redis.hdel(`${REDIS_PREFIX}interfaces`, localAddress);

                await request.flash({ type: 'info', message: `Address removed` });
                return h.redirect('/admin/config/network');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't delete address. Try again.` });
                request.logger.error({ msg: 'Failed to delete address', err, localAddress: request.payload.localAddress, remoteAddress: request.app.ip });
                return h.redirect('/admin/config/network');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't delete address. Try again.` });
                    request.logger.error({ msg: 'Failed to delete address', err });

                    return h.redirect('/admin/config/network').takeover();
                },

                payload: Joi.object({
                    localAddress: Joi.string().ip({
                        version: ['ipv4', 'ipv6'],
                        cidr: 'forbidden'
                    })
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/imap-proxy',
        async handler(request, h) {
            let values = {
                imapProxyServerEnabled: await settings.get('imapProxyServerEnabled'),
                imapProxyServerPassword: await settings.get('imapProxyServerPassword'),
                imapProxyServerPort: await settings.get('imapProxyServerPort'),
                imapProxyServerHost: await settings.get('imapProxyServerHost'),
                imapProxyServerProxy: await settings.get('imapProxyServerProxy'),
                imapProxyServerTLSEnabled: await settings.get('imapProxyServerTLSEnabled')
            };

            let availableAddresses = new Set(
                Object.values(os.networkInterfaces())
                    .flatMap(entry => entry)
                    .map(entry => entry.address)
            );
            availableAddresses.add('0.0.0.0');

            let hostname = await h.serviceDomain();
            let certificateData = await h.getCertificate();

            return h.view(
                'config/imap-proxy',
                {
                    pageTitle: 'IMAP Proxy',
                    menuConfig: true,
                    menuConfigImapProxy: true,

                    values,

                    serverState: await getServerStatus('imapProxy'),
                    availableAddresses: Array.from(availableAddresses).join(','),

                    serviceDomain: hostname,
                    serviceUrl: await settings.get('serviceUrl'),
                    certificateData
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/imap-proxy',
        async handler(request, h) {
            try {
                let existingSetup = {};
                let hasServerChanges = false;

                const systemKeys = ['imapProxyServerEnabled', 'imapProxyServerPort', 'imapProxyServerHost', 'imapProxyServerTLSEnabled'];
                for (let key of systemKeys) {
                    existingSetup[key] = await settings.get(key);
                }

                for (let key of Object.keys(request.payload)) {
                    await settings.set(key, request.payload[key]);
                    if (systemKeys.includes(key) && request.payload[key] !== existingSetup[key]) {
                        hasServerChanges = true;
                    }
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                if (hasServerChanges) {
                    // request server restart
                    try {
                        await call({ cmd: 'imapProxyReload' });
                    } catch (err) {
                        request.logger.error({ msg: 'Reload request failed', action: 'request_reload_imap_proxy', err });
                    }
                }

                return h.redirect('/admin/config/imap-proxy');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let availableAddresses = new Set(
                    Object.values(os.networkInterfaces())
                        .flatMap(entry => entry)
                        .map(entry => entry.address)
                );
                availableAddresses.add('0.0.0.0');

                let hostname = await h.serviceDomain();
                let certificateData = await h.getCertificate();

                return h.view(
                    'config/imap-proxy',
                    {
                        pageTitle: 'IMAP Proxy',
                        menuConfig: true,
                        menuConfigImapProxy: true,

                        serverState: await getServerStatus('imapProxy'),
                        availableAddresses: Array.from(availableAddresses).join(','),

                        serviceDomain: hostname,
                        serviceUrl: await settings.get('serviceUrl'),
                        certificateData
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let availableAddresses = new Set(
                        Object.values(os.networkInterfaces())
                            .flatMap(entry => entry)
                            .map(entry => entry.address)
                    );
                    availableAddresses.add('0.0.0.0');

                    let hostname = await h.serviceDomain();
                    let certificateData = await h.getCertificate();

                    return h
                        .view(
                            'config/imap-proxy',
                            {
                                pageTitle: 'IMAP Proxy',
                                menuConfig: true,
                                menuConfigImapProxy: true,

                                serverState: await getServerStatus('imapProxy'),
                                availableAddresses: Array.from(availableAddresses).join(','),

                                serviceDomain: hostname,
                                serviceUrl: await settings.get('serviceUrl'),
                                certificateData,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configImapProxySchema)
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/smtp',
        async handler(request, h) {
            let values = {
                smtpServerEnabled: await settings.get('smtpServerEnabled'),
                smtpServerPassword: await settings.get('smtpServerPassword'),
                smtpServerAuthEnabled: await settings.get('smtpServerAuthEnabled'),
                smtpServerPort: await settings.get('smtpServerPort'),
                smtpServerHost: await settings.get('smtpServerHost'),
                smtpServerProxy: await settings.get('smtpServerProxy'),
                smtpServerTLSEnabled: await settings.get('smtpServerTLSEnabled')
            };

            let availableAddresses = new Set(
                Object.values(os.networkInterfaces())
                    .flatMap(entry => entry)
                    .map(entry => entry.address)
            );
            availableAddresses.add('0.0.0.0');

            let hostname = await h.serviceDomain();
            let certificateData = await h.getCertificate();

            return h.view(
                'config/smtp',
                {
                    pageTitle: 'SMTP Interface',
                    menuConfig: true,
                    menuConfigSmtp: true,

                    values,

                    serverState: await getServerStatus('smtp'),
                    availableAddresses: Array.from(availableAddresses).join(','),

                    serviceDomain: hostname,
                    serviceUrl: await settings.get('serviceUrl'),
                    certificateData
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/smtp',
        async handler(request, h) {
            try {
                let existingSetup = {};
                let hasServerChanges = false;

                const systemKeys = ['smtpServerEnabled', 'smtpServerPort', 'smtpServerHost', 'smtpServerTLSEnabled'];
                for (let key of systemKeys) {
                    existingSetup[key] = await settings.get(key);
                }

                for (let key of Object.keys(request.payload)) {
                    await settings.set(key, request.payload[key]);
                    if (systemKeys.includes(key) && request.payload[key] !== existingSetup[key]) {
                        hasServerChanges = true;
                    }
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                if (hasServerChanges) {
                    // request server restart
                    try {
                        await call({ cmd: 'smtpReload' });
                    } catch (err) {
                        request.logger.error({ msg: 'Reload request failed', action: 'request_reload_smtp', err });
                    }
                }

                return h.redirect('/admin/config/smtp');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let availableAddresses = new Set(
                    Object.values(os.networkInterfaces())
                        .flatMap(entry => entry)
                        .map(entry => entry.address)
                );
                availableAddresses.add('0.0.0.0');

                let hostname = await h.serviceDomain();
                let certificateData = await h.getCertificate();

                return h.view(
                    'config/smtp',
                    {
                        pageTitle: 'SMTP Interface',
                        menuConfig: true,
                        menuConfigSmtp: true,

                        serverState: await getServerStatus('smtp'),
                        availableAddresses: Array.from(availableAddresses).join(','),

                        serviceDomain: hostname,
                        serviceUrl: await settings.get('serviceUrl'),
                        certificateData
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let availableAddresses = new Set(
                        Object.values(os.networkInterfaces())
                            .flatMap(entry => entry)
                            .map(entry => entry.address)
                    );
                    availableAddresses.add('0.0.0.0');

                    let hostname = await h.serviceDomain();
                    let certificateData = await h.getCertificate();

                    return h
                        .view(
                            'config/smtp',
                            {
                                pageTitle: 'SMTP Interface',
                                menuConfig: true,
                                menuConfigSmtp: true,

                                serverState: await getServerStatus('smtp'),
                                availableAddresses: Array.from(availableAddresses).join(','),

                                serviceDomain: hostname,
                                serviceUrl: await settings.get('serviceUrl'),
                                certificateData,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configSmtpSchema)
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/smtp/certificate',
        async handler(request, h) {
            try {
                let certificateData = await h.getCertificate(true);
                if (!certificateData) {
                    throw new Error(`Failed to provision a ceritifcate`);
                }

                return {
                    success: true,
                    domain: certificateData.domain,
                    fingerprint: certificateData.fingerprint,
                    altNames: certificateData.altNames,
                    validTo: certificateData.validTo && certificateData.validTo.toISOString(),
                    label: certificateData.label
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request syncing', err });
                return {
                    success: false,
                    error: err.message
                };
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/browser',
        async handler(request) {
            for (let key of ['serviceUrl', 'language', 'timezone']) {
                if (request.payload[key]) {
                    let existingValue = await settings.get(key);
                    if (existingValue === null) {
                        await settings.set(key, request.payload[key]);
                    }
                }
            }
            return { success: true };
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    serviceUrl: settingsSchema.serviceUrl.empty('').allow(false),

                    language: Joi.string()
                        .empty('')
                        .lowercase()
                        .regex(/^[a-z0-9]{1,5}([-_][a-z0-9]{1,15})?$/)
                        .allow(false),

                    timezone: Joi.string().empty('').allow(false).max(255)
                })
            }
        }
    });
}

module.exports = init;
