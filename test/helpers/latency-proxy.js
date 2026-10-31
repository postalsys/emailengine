'use strict';

// A TCP proxy that adds latency, holds traffic or cuts connections, for the multi-instance tier and
// the chaos runs. An instance whose Redis URL (or whose peers' view of its cluster address) points
// through one of these can be given a slow Redis, a partition or a realistic cross-node hop without
// Docker or root.
//
// Delay keeps byte order: every chunk is released no earlier than `delay` after it arrived and
// never before the chunk ahead of it. Pausing holds the bytes (a black hole that later recovers);
// cutting resets every connection (a restart of whatever is behind the proxy).

const net = require('node:net');

class Direction {
    constructor(destination, proxy) {
        this.destination = destination;
        this.proxy = proxy;
        this.queue = [];
        this.timer = null;
    }

    push(chunk) {
        this.queue.push({ chunk, releaseAt: Date.now() + this.proxy.delay });
        this.pump();
    }

    pump() {
        if (this.timer || this.proxy.paused) {
            return;
        }
        while (this.queue.length) {
            const wait = this.queue[0].releaseAt - Date.now();
            if (wait > 0) {
                this.timer = setTimeout(() => {
                    this.timer = null;
                    this.pump();
                }, wait);
                return;
            }
            const { chunk } = this.queue.shift();
            if (!this.destination.destroyed) {
                this.destination.write(chunk);
            }
        }
    }

    stop() {
        clearTimeout(this.timer);
        this.timer = null;
        this.queue = [];
    }
}

/**
 * @param {Object} opts
 * @param {string} [opts.host] - Target host, 127.0.0.1 by default
 * @param {number} opts.port - Target port
 * @param {number} [opts.delay] - Milliseconds added in each direction
 * @param {number} [opts.listenPort] - 0 picks a free port
 * @returns {Promise<Object>} The proxy
 */
async function startLatencyProxy(opts) {
    const pairs = new Set();

    const proxy = {
        delay: opts.delay || 0,
        paused: false,
        port: null
    };

    const server = net.createServer(client => {
        const upstream = net.connect(opts.port, opts.host || '127.0.0.1');
        const up = new Direction(upstream, proxy);
        const down = new Direction(client, proxy);
        const pair = { client, upstream, up, down };
        pairs.add(pair);

        const close = () => {
            pairs.delete(pair);
            up.stop();
            down.stop();
            client.destroy();
            upstream.destroy();
        };

        client.on('data', chunk => up.push(chunk));
        upstream.on('data', chunk => down.push(chunk));
        client.on('error', close);
        upstream.on('error', close);
        client.on('close', close);
        upstream.on('close', close);
    });

    await new Promise(resolve => server.listen(opts.listenPort || 0, '127.0.0.1', resolve));
    proxy.port = server.address().port;

    return Object.assign(proxy, {
        get connections() {
            return pairs.size;
        },

        setDelay(ms) {
            proxy.delay = Math.max(0, Number(ms) || 0);
        },

        /** Holds every byte until resume(); connections stay open */
        pause() {
            proxy.paused = true;
        },

        resume() {
            proxy.paused = false;
            for (const pair of pairs) {
                pair.up.pump();
                pair.down.pump();
            }
        },

        /** Resets every open connection; new ones are accepted again at once */
        cut() {
            for (const pair of [...pairs]) {
                if (pair.client.resetAndDestroy) {
                    pair.client.resetAndDestroy();
                } else {
                    pair.client.destroy();
                }
                pair.upstream.destroy();
            }
        },

        async stop() {
            proxy.cut();
            await new Promise(resolve => server.close(() => resolve()));
        }
    });
}

module.exports = { startLatencyProxy };
