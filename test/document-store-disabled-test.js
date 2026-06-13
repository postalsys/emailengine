'use strict';

// Verifies the default-off behavior of the deprecated Document Store feature gate.
//
// lib/routes-ui.js only registers the /admin/config/document-store* UI routes when the
// feature is enabled (--documentStore.enabled / EENGINE_DOCUMENT_STORE_ENABLED). The gate
// is read once at module load, and the test suite runs with the feature ON (config/test.toml),
// so we assert the OFF behavior in a child process that forces the env flag off (env overrides
// the config value). This guards the gating in lib/routes-ui.js against regressions.

const test = require('node:test');
const assert = require('node:assert').strict;
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const HELPER = path.join(__dirname, 'helpers', 'capture-ui-routes.js');

function captureRoutesWithFlag(value) {
    const out = execFileSync(process.execPath, [HELPER], {
        env: Object.assign({}, process.env, { EENGINE_DOCUMENT_STORE_ENABLED: value }),
        encoding: 'utf-8',
        timeout: 30000
    });
    return JSON.parse(out);
}

test('Document Store UI routes are gated by the feature flag', async t => {
    await t.test('no document-store routes are registered when the feature is disabled', () => {
        const routes = captureRoutesWithFlag('false');

        const documentStoreRoutes = routes.filter(route => /\/admin\/config\/document-store/.test(route));
        assert.deepEqual(documentStoreRoutes, [], `expected no document-store routes when disabled, got ${JSON.stringify(documentStoreRoutes)}`);

        // Core admin routes must still be registered - only the document store ones drop out.
        assert.ok(routes.includes('GET /admin'), 'core /admin route should still be registered');
        assert.ok(routes.includes('GET /admin/config/webhooks'), 'unrelated config routes should still be registered');
    });

    await t.test('document-store routes are registered when the feature is enabled', () => {
        const routes = captureRoutesWithFlag('true');

        assert.ok(routes.includes('GET /admin/config/document-store'), 'document-store config route should be registered when enabled');
        assert.ok(routes.includes('POST /admin/config/document-store'), 'document-store config POST route should be registered when enabled');
    });
});
