'use strict';

const config = require('@zone-eu/wild-config');
const settings = require('../settings');
const { hasEnvValue, readEnvValue, getBoolean } = require('../tools');

// Deployment-level gate for the MCP (Model Context Protocol) endpoint. When this is false the
// /mcp routes are not registered at all, so the surface does not exist on the instance. Set via
// the --mcp.enabled CLI flag / [mcp] enabled config or EENGINE_MCP_ENABLED. Defaults to true -
// unlike the Document Store gate this one exists for operators who want the endpoint compiled
// out of the route table, not to hide an unfinished feature.
//
// The runtime on/off switch is the `mcpEnabled` setting below, which starts out false and is
// flipped in the admin UI, so a fresh instance does not expose a new surface until someone
// turns it on.
const mcpFeatureEnabled = hasEnvValue('EENGINE_MCP_ENABLED')
    ? getBoolean(readEnvValue('EENGINE_MCP_ENABLED'))
    : getBoolean(config.mcp ? config.mcp.enabled : true);

// Effective runtime state: the feature must be available (gate) AND enabled in settings. When
// the gate is off this is always false, mirroring isDocumentStoreEnabled() in
// lib/document-store.js.
const isMcpEnabled = async () => mcpFeatureEnabled && !!(await settings.get('mcpEnabled'));

module.exports = { mcpFeatureEnabled, isMcpEnabled };
