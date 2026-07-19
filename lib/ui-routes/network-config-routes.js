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
const { registerSettingsPage } = require('./settings-page');

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

    registerSettingsPage(server, {
        path: '/admin/config/network',
        view: 'config/network',
        pageTitle: 'Network',
        menuKey: 'menuConfigNetwork',
        schema: {
            imapStrategy: settingsSchema.imapStrategy.default('default'),
            smtpStrategy: settingsSchema.smtpStrategy.default('default'),
            localAddresses: settingsSchema.localAddresses.default([]),

            proxyUrl: settingsSchema.proxyUrl,
            smtpEhloName: settingsSchema.smtpEhloName,
            proxyEnabled: settingsSchema.proxyEnabled,

            httpProxyEnabled: settingsSchema.httpProxyEnabled,
            httpProxyUrl: settingsSchema.httpProxyUrl
        },

        async loadValues() {
            const storedValues = await settings.getMulti(
                'smtpStrategy',
                'imapStrategy',
                'proxyEnabled',
                'proxyUrl',
                'smtpEhloName',
                'httpProxyEnabled',
                'httpProxyUrl',
                'localAddresses'
            );

            return {
                smtpStrategy: storedValues.smtpStrategy || 'default',
                imapStrategy: storedValues.imapStrategy || 'default',

                proxyEnabled: storedValues.proxyEnabled,
                proxyUrl: storedValues.proxyUrl,
                smtpEhloName: storedValues.smtpEhloName,
                httpProxyEnabled: storedValues.httpProxyEnabled,
                httpProxyUrl: storedValues.httpProxyUrl,

                localAddresses: [].concat(storedValues.localAddresses || [])
            };
        },

        async viewContext(request, values) {
            return {
                smtpStrategies: ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: values.smtpStrategy === entry.key }, entry)),
                imapStrategies: ADDRESS_STRATEGIES.map(entry => Object.assign({ selected: values.imapStrategy === entry.key }, entry)),

                addresses: await listPublicInterfaces([].concat(values.localAddresses || [])),
                addressListTemplate: cachedTemplates.addressList,
                defaultSmtpEhloName: await getServiceHostname()
            };
        },

        async applySettings(request) {
            let data = {};
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
                data[key] = request.payload[key];
            }
            await settings.setMulti(data);

            // Notify all workers (including this one) about the settings change; each reloads
            // its HTTP proxy agent via the 'settings' message handler.
            if (parentPort) {
                parentPort.postMessage({ cmd: 'settings', data: request.payload });
            }
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

    // Context shared by the SMTP server and IMAP proxy pages: live server state,
    // bindable interface addresses, and the TLS certificate for the service domain
    const serverPageContext = async (h, serverType) => {
        let availableAddresses = new Set(
            Object.values(os.networkInterfaces())
                .flatMap(entry => entry)
                .map(entry => entry.address)
        );
        availableAddresses.add('0.0.0.0');

        return {
            serverState: await getServerStatus(serverType),
            availableAddresses: Array.from(availableAddresses).join(','),

            serviceDomain: await h.serviceDomain(),
            serviceUrl: await settings.get('serviceUrl'),
            certificateData: await h.getCertificate()
        };
    };

    // Persist a server-settings payload and request a server restart when a key
    // that affects the listener (enabled/port/host/TLS) actually changed
    const applyServerSettings = async (request, systemKeys, reloadCmd, reloadAction) => {
        const existingSetup = await settings.getMulti(...systemKeys);
        const hasServerChanges = systemKeys.some(key => request.payload[key] !== existingSetup[key]);

        await settings.setMulti(request.payload);

        if (hasServerChanges) {
            // request server restart
            try {
                await call({ cmd: reloadCmd });
            } catch (err) {
                request.logger.error({ msg: 'Reload request failed', action: reloadAction, err });
            }
        }
    };

    registerSettingsPage(server, {
        path: '/admin/config/imap-proxy',
        view: 'config/imap-proxy',
        pageTitle: 'IMAP Proxy',
        menuKey: 'menuConfigImapProxy',
        schema: configImapProxySchema,

        async loadValues() {
            return await settings.getMulti(
                'imapProxyServerEnabled',
                'imapProxyServerPassword',
                'imapProxyServerPort',
                'imapProxyServerHost',
                'imapProxyServerProxy',
                'imapProxyServerTLSEnabled'
            );
        },

        viewContext: async (request, values, h) => await serverPageContext(h, 'imapProxy'),

        async applySettings(request) {
            await applyServerSettings(
                request,
                ['imapProxyServerEnabled', 'imapProxyServerPort', 'imapProxyServerHost', 'imapProxyServerTLSEnabled'],
                'imapProxyReload',
                'request_reload_imap_proxy'
            );
        }
    });

    registerSettingsPage(server, {
        path: '/admin/config/smtp',
        view: 'config/smtp',
        pageTitle: 'SMTP Server',
        menuKey: 'menuConfigSmtp',
        schema: configSmtpSchema,

        async loadValues() {
            return await settings.getMulti(
                'smtpServerEnabled',
                'smtpServerPassword',
                'smtpServerAuthEnabled',
                'smtpServerPort',
                'smtpServerHost',
                'smtpServerProxy',
                'smtpServerTLSEnabled'
            );
        },

        viewContext: async (request, values, h) => await serverPageContext(h, 'smtp'),

        async applySettings(request) {
            await applyServerSettings(
                request,
                ['smtpServerEnabled', 'smtpServerPort', 'smtpServerHost', 'smtpServerTLSEnabled'],
                'smtpReload',
                'request_reload_smtp'
            );
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
