'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): a throwaway localhost HTTP
// server that records what a client actually put on the wire.
//
// Used by the OAuth2 request tests to assert the bytes and headers EmailEngine sends to Gmail /
// Microsoft Graph, without reaching a real provider.

const http = require('node:http');

/**
 * Starts a server that records the method, path, headers and raw body of each request.
 *
 * @param {Function} [responder] - (res, captured) => void; writes the response. Defaults to
 *                                 202 Accepted with an empty body, what Graph returns for sendMail.
 * @returns {Promise<Object>} { server, baseUrl, getCaptured }
 */
async function startCapturingServer(responder) {
    let captured = null;

    const respond =
        responder ||
        (res => {
            res.writeHead(202);
            res.end();
        });

    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
            captured = {
                method: req.method,
                path: req.url,
                headers: req.headers,
                body: Buffer.concat(chunks)
            };
            respond(res, captured);
        });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    return {
        server,
        baseUrl: `http://127.0.0.1:${port}`,
        getCaptured: () => captured
    };
}

async function stopServer(server) {
    await new Promise(resolve => server.close(resolve));
}

/**
 * Runs `fn` against a freshly started capturing server and always shuts it down afterwards.
 *
 * @param {Function|null} responder - see startCapturingServer
 * @param {Function} fn - async ({ baseUrl, getCaptured }) => void
 */
async function withCapturingServer(responder, fn) {
    const { server, baseUrl, getCaptured } = await startCapturingServer(responder);
    try {
        await fn({ baseUrl, getCaptured });
    } finally {
        await stopServer(server);
    }
}

module.exports = { startCapturingServer, stopServer, withCapturingServer };
