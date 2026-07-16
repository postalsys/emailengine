'use strict';

// Shared helpers used by more than one extracted UI route module - and still by
// lib/routes-ui.js for the route groups not yet extracted. Lifting these here lets each
// consumer import the single canonical copy instead of the monolith, so a route group can
// be extracted without stranding a helper its sibling groups still need. Pure functions
// and cached data only - this module registers no routes.
//
// Every symbol below was moved verbatim from lib/routes-ui.js. The only change is in
// cachedTemplates: its __dirname-relative paths gain one extra '..' because this file
// lives one directory deeper (lib/ui-routes/) than the original (lib/).

const Boom = require('@hapi/boom');
const util = require('util');
const fs = require('fs');
const pathlib = require('path');
const psl = require('psl');

const settings = require('../settings');
const { redis } = require('../db');
const { REDIS_PREFIX } = require('../consts');
const { oauth2ProviderData } = require('../oauth2-apps');
const exampleDocumentsPayloads = require('../payload-examples-documents.json');

const OPEN_AI_MODELS = [
    {
        name: 'GPT-3 (instruct)',
        id: 'gpt-3.5-turbo-instruct'
    },

    {
        name: 'GPT-3 (chat)',
        id: 'gpt-3.5-turbo'
    },

    {
        name: 'GPT-4',
        id: 'gpt-4'
    }
];

const cachedTemplates = {
    addressList: fs.readFileSync(pathlib.join(__dirname, '..', '..', 'views', 'partials', 'address_list.hbs'), 'utf-8'),
    testSend: fs.readFileSync(pathlib.join(__dirname, '..', '..', 'views', 'partials', 'test_send.hbs'), 'utf-8')
};

const getOpenAiModels = async (models, selectedModel) => {
    let modelList = (await settings.get('openAiModels')) || structuredClone(models);

    if (selectedModel && !modelList.find(model => model.id === selectedModel)) {
        modelList.unshift({
            name: selectedModel,
            id: selectedModel
        });
    }

    return modelList.map(model => {
        model.selected = model.id === selectedModel;
        return model;
    });
};

function formatAccountData(account, gt) {
    account.type = {};

    if (account.oauth2 && account.oauth2.app) {
        let providerData = oauth2ProviderData(account.oauth2.app.provider);
        account.type = providerData;
    } else if (account.oauth2 && account.oauth2.provider) {
        account.type = oauth2ProviderData(account.oauth2.provider);
    } else if (account.imap && !account.imap.disabled) {
        account.type.icon = 'icon-[tabler--mail]';
        account.type.name = 'IMAP';
        account.type.comment = psl.get(account.imap.host) || account.imap.host;
    } else if (account.smtp) {
        account.type.icon = 'icon-[tabler--send]';
        account.type.name = 'SMTP';
        account.type.comment = psl.get(account.smtp.host) || account.smtp.host;
    } else if (account.oauth2 && account.oauth2.auth && account.oauth2.auth.delegatedAccount) {
        account.type.icon = 'icon-[tabler--arrow-right-circle]';
        account.type.name = gt.gettext('Delegated');
        account.type.comment = util.format(gt.gettext('Using credentials from "%s"'), account.oauth2.auth.delegatedAccount);
    } else {
        account.type.name = 'N/A';
    }

    // composed hover label for the type icon (used by ui/tooltip in the views)
    account.type.label = `${account.type.name || ''}${account.type.comment ? ` (${account.type.comment})` : ''}`;

    switch (account.state) {
        case 'init':
            account.stateLabel = {
                type: 'info',
                name: 'Initializing',
                spinner: true
            };
            break;

        case 'connecting':
            account.stateLabel = {
                type: 'info',
                name: 'Connecting'
            };
            break;

        case 'syncing':
            account.stateLabel = {
                type: 'info',
                name: 'Syncing',
                spinner: true
            };
            break;

        case 'connected':
            account.stateLabel = {
                type: 'success',
                name: 'Connected'
            };
            break;

        case 'disabled':
            account.stateLabel = {
                type: 'neutral',
                name: 'Disabled',
                error: account.disabledReason
            };
            break;

        case 'authenticationError':
        case 'connectError': {
            let errorMessage = account.lastErrorState ? account.lastErrorState.response : false;
            if (account.lastErrorState) {
                switch (account.lastErrorState.serverResponseCode) {
                    case 'ETIMEDOUT':
                        errorMessage = gt.gettext('Connection timed out. This usually occurs if you are behind a firewall or connecting to the wrong port.');
                        break;
                    case 'ClosedAfterConnectTLS':
                        errorMessage = gt.gettext('The server unexpectedly closed the connection.');
                        break;
                    case 'ClosedAfterConnectText':
                        errorMessage = gt.gettext(
                            'The server unexpectedly closed the connection. This usually happens when attempting to connect to a TLS port without TLS enabled.'
                        );
                        break;
                    case 'ECONNREFUSED':
                        errorMessage = gt.gettext(
                            'The server refused the connection. This typically occurs if the server is not running, is overloaded, or you are connecting to the wrong host or port.'
                        );
                        break;
                }
            }

            account.stateLabel = {
                type: 'error',
                name: 'Failed',
                error: errorMessage
            };
            break;
        }
        case 'unset':
            account.stateLabel = {
                type: 'neutral',
                name: 'Not syncing'
            };
            break;
        case 'disconnected':
            account.stateLabel = {
                type: 'warning',
                name: 'Disconnected'
            };
            break;
        case 'paused':
            account.stateLabel = {
                type: 'neutral',
                name: 'Paused'
            };
            break;
        default:
            account.stateLabel = {
                type: 'neutral',
                name: 'N/A'
            };
            break;
    }

    // Check if IMAP was disabled due to errors - override state label to show error
    if (account.imap && account.imap.disabled && account.lastErrorState) {
        account.stateLabel = {
            type: 'error',
            name: 'Failed',
            error: account.lastErrorState.description || account.lastErrorState.response
        };
    }

    if (account.oauth2) {
        account.oauth2.scopes = []
            .concat(account.oauth2.scope || [])
            .concat(account.oauth2.scopes || [])
            .flatMap(entry => entry.split(/\s+/))
            .map(entry => entry.trim())
            .filter(entry => entry);

        account.oauth2.expiresStr = account.oauth2.expires ? account.oauth2.expires.toISOString() : false;
        account.oauth2.generatedStr = account.oauth2.generated ? account.oauth2.generated.toISOString() : false;

        if (account.outlookSubscription) {
            account.outlookSubscription.subscriptionExpiresStr = account.outlookSubscription.expirationDateTime
                ? account.outlookSubscription.expirationDateTime.toISOString()
                : false;

            let state = account.outlookSubscription.state || {};

            account.outlookSubscription.isValid =
                state.state !== 'error' && account.outlookSubscription.expirationDateTime && account.outlookSubscription.expirationDateTime > new Date();

            account.outlookSubscription.stateLabel = (state.state || '').replace(/^./, c => c.toUpperCase());

            if ((state.state === 'created' && !account.outlookSubscription.expirationDateTime) || account.outlookSubscription.expirationDateTime < new Date()) {
                account.outlookSubscription.stateLabel = 'Expired';
            }
        }
    }

    return account;
}

function formatServerState(state, payload) {
    switch (state) {
        case 'suspended':
        case 'exited':
        case 'disabled':
            return {
                type: 'warning',
                name: state
            };

        case 'spawning':
        case 'initializing':
            return {
                type: 'info',
                name: state,
                spinner: true
            };

        case 'listening':
            return {
                type: 'success',
                name: state
            };

        case 'failed':
            return {
                type: 'error',
                name: state,
                error: (payload && payload.error && payload.error.message) || null
            };

        default:
            return {
                type: 'neutral',
                name: 'N/A'
            };
    }
}

async function getExampleDocumentsPayloads() {
    let date = new Date().toISOString();

    let examplePayloads = structuredClone(exampleDocumentsPayloads);

    examplePayloads.forEach(payload => {
        if (payload && payload.content) {
            if (typeof payload.content.date === 'string') {
                payload.content.date = date;
            }

            if (typeof payload.content.created === 'string') {
                payload.content.created = date;
            }
        }
    });
    return examplePayloads;
}

async function getServerStatus(type) {
    let serverStatus = await redis.hgetall(`${REDIS_PREFIX}${type}`);
    let state = (serverStatus && serverStatus.state) || 'disabled';
    let payload;
    try {
        payload = (serverStatus && typeof serverStatus.payload === 'string' && JSON.parse(serverStatus.payload)) || {};
    } catch (err) {
        // ignore
    }

    return { state, payload, label: formatServerState(state, payload) };
}

function throwAsBoom(err) {
    if (Boom.isBoom(err)) {
        throw err;
    }
    let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
    if (err.code) {
        error.output.payload.code = err.code;
    }
    throw error;
}

module.exports = {
    OPEN_AI_MODELS,
    cachedTemplates,
    getOpenAiModels,
    formatAccountData,
    getExampleDocumentsPayloads,
    getServerStatus,
    throwAsBoom
};
