'use strict';

const settings = require('./settings');
const { Client: ElasticSearch } = require('@elastic/elasticsearch');
const { ensureIndex } = require('./es');

const clientCache = { version: -1, config: false, client: false, index: false };

const getESClient = async logger => {
    const documentStoreVersion = (await settings.get('documentStoreVersion')) || 0;
    if (clientCache.version === documentStoreVersion) {
        return clientCache;
    }

    let documentStoreEnabled = await settings.get('documentStoreEnabled');
    let documentStoreUrl = await settings.get('documentStoreUrl');

    if (!documentStoreEnabled || !documentStoreUrl) {
        clientCache.version = documentStoreVersion;
        clientCache.client = false;
        clientCache.index = false;
        return clientCache;
    }

    clientCache.index = (await settings.get('documentStoreIndex')) || 'emailengine';

    let documentStoreAuthEnabled = await settings.get('documentStoreAuthEnabled');
    let documentStoreUsername = await settings.get('documentStoreUsername');
    let documentStorePassword = await settings.get('documentStorePassword');

    clientCache.config = {
        node: { url: new URL(documentStoreUrl), tls: { rejectUnauthorized: false } },
        auth:
            documentStoreAuthEnabled && documentStoreUsername
                ? {
                      username: documentStoreUsername,
                      password: documentStorePassword
                  }
                : false
    };

    clientCache.version = documentStoreVersion;
    clientCache.client = new ElasticSearch(clientCache.config);

    // ensure proper index settings
    let indexResult = await ensureIndex(clientCache.client, clientCache.index);
    if (!indexResult || !indexResult.exists) {
        logger.info({ msg: 'Updated document index', index: clientCache.index, result: indexResult });
    }

    return clientCache;
};

module.exports = { getESClient };
