'use strict';

// Records every webhook a fleet delivers, for the multi-instance tier and the load and chaos runs.
//
// Messages injected by a test carry a token in their subject (`[ledger:<token>]`), so a messageNew
// delivery can be matched to the injection that caused it without trusting anything the fleet
// computed. That makes "exactly once" and "how long did it take" one lookup each, and a duplicate
// shows up as a second entry under the same account and token.

const http = require('node:http');
const crypto = require('node:crypto');

const TOKEN_RE = /\[ledger:([a-z0-9]+)\]/;

// First delivery of every webhook job, in arrival order
function distinctEmissions(entries) {
    const seen = new Set();
    return entries.filter(entry => {
        if (!entry.deliveryId) {
            return true;
        }
        if (seen.has(entry.deliveryId)) {
            return false;
        }
        seen.add(entry.deliveryId);
        return true;
    });
}

function newToken() {
    return crypto.randomBytes(6).toString('hex');
}

/**
 * Starts the receiving server.
 * @param {Object} [opts]
 * @param {number} [opts.port] - 0 picks a free port
 * @param {number} [opts.status] - Status every delivery is answered with
 * @returns {Promise<Object>} The ledger
 */
async function startLedger(opts = {}) {
    // `${account}\n${token}` -> [{ receivedAt, event, instance, attempt }]
    const deliveries = new Map();
    const events = [];
    const waiters = new Set();

    const notify = () => {
        for (const waiter of waiters) {
            waiter();
        }
    };

    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
            const receivedAt = Date.now();
            let payload;
            try {
                payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            } catch (err) {
                payload = null;
            }

            if (payload) {
                const entry = {
                    receivedAt,
                    event: payload.event,
                    account: payload.account,
                    attempt: Number(req.headers['x-ee-wh-attempts-made']) || 0,
                    // A retried delivery keeps its job id, two emissions of one event do not
                    deliveryId: req.headers['x-ee-wh-id'] || null,
                    payload
                };
                events.push(entry);

                const subject = (payload.data && payload.data.subject) || '';
                const match = TOKEN_RE.exec(subject);
                if (payload.event === 'messageNew' && match) {
                    const key = `${payload.account}\n${match[1]}`;
                    if (!deliveries.has(key)) {
                        deliveries.set(key, []);
                    }
                    deliveries.get(key).push(entry);
                }
                notify();
            }

            res.writeHead(opts.status || 200, { 'Content-Type': 'application/json' });
            res.end('{"ok":true}');
        });
    });

    await new Promise(resolve => server.listen(opts.port || 0, '127.0.0.1', resolve));
    const port = server.address().port;

    return {
        port,
        url: `http://127.0.0.1:${port}/webhooks`,
        events,

        newToken,
        subjectFor(token, label) {
            return `${label || 'Ledger message'} [ledger:${token}]`;
        },

        /** Every messageNew delivery for an account and token */
        deliveriesFor(account, token) {
            return deliveries.get(`${account}\n${token}`) || [];
        },

        /** Distinct emissions for an account and token: retries of one job count once */
        emissionsFor(account, token) {
            return distinctEmissions(deliveries.get(`${account}\n${token}`) || []);
        },

        /** Resolves once `predicate()` holds, or rejects after `timeout` */
        waitFor(predicate, timeout = 30000, label = 'ledger condition') {
            if (predicate()) {
                return Promise.resolve();
            }
            return new Promise((resolve, reject) => {
                let timer;
                const check = () => {
                    if (predicate()) {
                        clearTimeout(timer);
                        waiters.delete(check);
                        resolve();
                    }
                };
                timer = setTimeout(() => {
                    waiters.delete(check);
                    reject(new Error(`Timed out after ${timeout}ms waiting for ${label}`));
                }, timeout);
                waiters.add(check);
            });
        },

        /**
         * Summary of the injections a run made: each one `{ account, token, injectedAt }`.
         * Returns the latencies of first deliveries and the accounts and tokens that were
         * delivered more than once or not at all
         */
        reconcile(injections) {
            const latencies = [];
            const duplicates = [];
            const missing = [];
            for (const { account, token, injectedAt } of injections) {
                const found = distinctEmissions(deliveries.get(`${account}\n${token}`) || []);
                if (!found.length) {
                    missing.push({ account, token, injectedAt });
                    continue;
                }
                if (found.length > 1) {
                    duplicates.push({ account, token, count: found.length });
                }
                latencies.push(found[0].receivedAt - injectedAt);
            }
            return { latencies, duplicates, missing };
        },

        reset() {
            deliveries.clear();
            events.length = 0;
        },

        async stop() {
            await new Promise(resolve => server.close(() => resolve()));
            server.closeAllConnections?.();
        }
    };
}

module.exports = { startLedger, newToken };
