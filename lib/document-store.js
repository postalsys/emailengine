'use strict';

const config = require('@zone-eu/wild-config');
const settings = require('./settings');
const { Client: ElasticSearch } = require('@elastic/elasticsearch');
const { ensureIndex } = require('./es');
const { hasEnvValue, readEnvValue, getBoolean } = require('./tools');

// Deployment-level gate for the deprecated Document Store feature. When this is false the
// "documents" worker is not spawned, document-store-only endpoints are not registered, and
// all runtime document-store code takes its existing "disabled" path. Set via the
// --documentStore.enabled CLI flag / [documentStore] enabled config or EENGINE_DOCUMENT_STORE_ENABLED.
const documentStoreFeatureEnabled = hasEnvValue('EENGINE_DOCUMENT_STORE_ENABLED')
    ? getBoolean(readEnvValue('EENGINE_DOCUMENT_STORE_ENABLED'))
    : getBoolean(config.documentStore && config.documentStore.enabled);

// Effective runtime state: the feature must be available (gate) AND enabled in settings.
// When the gate is off this is always false, so callers reuse the already-tested
// "documentStoreEnabled is false" code paths.
const isDocumentStoreEnabled = async () => documentStoreFeatureEnabled && !!(await settings.get('documentStoreEnabled'));

const clientCache = { version: -1, config: false, client: false, index: false };

const getESClient = async logger => {
    // Feature gate is off: behave exactly as a disabled document store. Checked before any
    // Redis access so disabled deployments do not pay a round-trip on every getESClient call.
    if (!documentStoreFeatureEnabled) {
        return clientCache;
    }

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

module.exports = { getESClient, documentStoreFeatureEnabled, isDocumentStoreEnabled };
