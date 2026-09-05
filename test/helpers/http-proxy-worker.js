'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): a worker thread that reports
// which proxy lib/tools.js built its dispatchers for at load time and fetches one URL through them.
// Spawned by test/http-proxy-test.js with { httpProxyUrl, targetUrl } in workerData, the way
// server.js spawns the real workers; the parent terminates it once the report arrives.

const { parentPort, workerData } = require('node:worker_threads');
const { fetch: fetchCmd } = require('undici');
const { httpAgent } = require('../../lib/tools');

fetchCmd(workerData.targetUrl, { dispatcher: httpAgent.retry })
    .then(async res => {
        await res.text();
        return { ok: res.ok };
    })
    .catch(err => ({ ok: false, error: err.message }))
    .then(result => parentPort.postMessage(Object.assign({ proxyUrl: httpAgent.proxyUrl }, result)));
