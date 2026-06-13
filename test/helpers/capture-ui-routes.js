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

function captureRoutes() {
    const captured = [];

    const record = cfg => {
        if (Array.isArray(cfg)) {
            cfg.forEach(record);
            return;
        }
        const methods = Array.isArray(cfg.method) ? cfg.method : [cfg.method];
        for (const method of methods) {
            captured.push(`${String(method).toUpperCase()} ${cfg.path}`);
        }
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

    return captured;
}

module.exports = { captureRoutes };

if (require.main === module) {
    const routes = captureRoutes();
    // Use writeSync so the output is fully flushed before the forced exit below.
    fs.writeSync(1, JSON.stringify(routes));
    process.exit(0);
}
