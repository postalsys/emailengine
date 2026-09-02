'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): captures the list of
// "METHOD path" pairs that lib/routes-ui.js registers, in registration order and WITHOUT
// de-duplication (so callers can detect duplicate registrations), using a bare mock Hapi
// server. Route registration is synchronous and never touches Redis or the `call` RPC, so
// the mock is sufficient.
//
// When run directly as a script it prints the captured routes as JSON to stdout and
// force-exits (requiring routes-ui.js transitively opens Redis/BullMQ handles). The
// document-store-disabled test runs this in a child process with
// EENGINE_DOCUMENT_STORE_ENABLED=false to assert the document store routes are gated off.

const fs = require('fs');

// Registration runs once per process: routes-ui.js is required and invoked a single time, and
// both accessors below read the same capture.
let capture = null;

function captureAll() {
    if (capture) {
        return capture;
    }

    const configs = [];

    const record = cfg => {
        if (Array.isArray(cfg)) {
            cfg.forEach(record);
            return;
        }
        configs.push(cfg);
    };

    const mockServer = new Proxy(
        {
            route: record,
            auth: { settings: { default: null }, default() {} }
        },
        {
            get(target, prop) {
                if (prop in target) {
                    return target[prop];
                }
                return () => {};
            }
        }
    );

    const mockCall = async () => ({});

    const routesUi = require('../../lib/routes-ui');
    routesUi(mockServer, mockCall);

    capture = configs;
    return capture;
}

// "METHOD path" pairs in registration order, without de-duplication, so callers can detect a
// route registered twice
function captureRoutes() {
    return captureAll().flatMap(cfg => [].concat(cfg.method).map(method => `${String(method).toUpperCase()} ${cfg.path}`));
}

// The full route configurations, for guardrails that look past method and path (e.g. which
// routes opt into header-based crumb validation)
function captureRouteConfigs() {
    return captureAll();
}

module.exports = { captureRoutes, captureRouteConfigs };

if (require.main === module) {
    const routes = captureRoutes();
    // Use writeSync so the output is fully flushed before the forced exit below.
    fs.writeSync(1, JSON.stringify(routes));
    process.exit(0);
}
