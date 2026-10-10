'use strict';

// Runs a worker module (workers/*.js) in a Worker thread and drives it over the RPC protocol the
// main thread uses. The workers boot on load and need a parentPort, so a test cannot require them.
// Calls the worker makes itself (account lookups, runIndex and the like) are answered with nothing.

const Path = require('path');
const { Worker, SHARE_ENV } = require('node:worker_threads');

function startWorker(name) {
    const worker = new Worker(Path.join(__dirname, '..', '..', 'workers', name), { env: SHARE_ENV, argv: [] });
    let mids = 0;
    const pending = new Map();

    const ready = new Promise((resolve, reject) => {
        worker.on('error', reject);
        worker.on('message', message => {
            if (!message) {
                return;
            }
            if (message.cmd === 'ready') {
                return resolve();
            }
            if (message.cmd === 'resp' && pending.has(message.mid)) {
                const { resolve: done } = pending.get(message.mid);
                pending.delete(message.mid);
                return done(message);
            }
            if (message.cmd === 'call') {
                worker.postMessage({ cmd: 'resp', mid: message.mid, response: null });
            }
        });
    });

    const call = message =>
        new Promise(resolve => {
            const mid = `test:${++mids}`;
            pending.set(mid, { resolve });
            worker.postMessage({ cmd: 'call', mid, message });
        });

    return { worker, ready, call };
}

module.exports = { startWorker };
