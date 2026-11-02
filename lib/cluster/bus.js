'use strict';

// The broadcast channel between the instances of a cluster.
//
// What the main thread used to fan out to its own workers only (a settings change, a change event
// for the live feeds, a listener or certificate reload, a Pub/Sub app change) is also published
// here, and every other instance re-dispatches it to its own workers the same way. An instance
// ignores what it published itself: it already dispatched it locally.
//
// Redis pub/sub is fire and forget. A message published while an instance is disconnected from
// Redis does not reach it, so nothing may depend on the bus alone for correctness: the ownership
// passes run on a timer whatever the bus says, and the security relevant settings are also checked
// on their own (see workers/api.js for the admin password).
//
// For the same reason the bus is optional at runtime. Subscribing needs channel access on the Redis
// user, which a Redis 7 ACL user has only with `allchannels` or an `&` pattern, and an instance
// without it still owns and serves its accounts. A subscribe that fails is logged once and retried
// on a timer, and nothing is published until it succeeds, so a missing permission costs one error
// line and the broadcasts, never the start-up of the instance.

const msgpack = require('../msgpack');

// How often a subscribe that failed is tried again
const DEFAULT_RETRY_INTERVAL = 30 * 1000;

class ClusterBus {
    /**
     * @param {Object} opts
     * @param {Object} opts.publisher - ioredis client used for PUBLISH
     * @param {Object} opts.subscriber - Dedicated ioredis client, put into subscriber mode
     * @param {string} opts.channel
     * @param {string} opts.instanceId
     * @param {Object} opts.logger
     * @param {Function} opts.onMessage - (type, data, from) for every message of another instance
     * @param {number} [opts.retryInterval] - Milliseconds between attempts to subscribe after a failure
     */
    constructor({ publisher, subscriber, channel, instanceId, logger, onMessage, retryInterval = DEFAULT_RETRY_INTERVAL }) {
        this.publisher = publisher;
        this.subscriber = subscriber;
        this.channel = channel;
        this.instanceId = instanceId;
        this.logger = logger;
        this.onMessage = onMessage;
        this.retryInterval = retryInterval;

        this.connected = false;
        this.stopped = false;
        this.retryTimer = null;
        this.failures = 0;

        this.onBuffer = (channel, buffer) => {
            if (channel.toString() !== this.channel) {
                return;
            }
            let message;
            try {
                message = msgpack.decode(buffer);
            } catch (err) {
                this.logger.warn({ msg: 'Dropped an unreadable cluster bus message', err });
                return;
            }
            if (!message || typeof message.t !== 'string' || message.f === this.instanceId) {
                return;
            }
            try {
                // A handler may be async; a rejection is reported here rather than left unhandled
                Promise.resolve(this.onMessage(message.t, message.d, message.f)).catch(err =>
                    this.logger.error({ msg: 'Failed to process a cluster bus message', type: message.t, from: message.f, err })
                );
            } catch (err) {
                this.logger.error({ msg: 'Failed to process a cluster bus message', type: message.t, from: message.f, err });
            }
        };
    }

    /** Whether broadcasts reach this instance and its own reach the others */
    isConnected() {
        return this.connected;
    }

    /**
     * Subscribes to the channel. Never rejects: an instance runs without the bus until subscribing
     * succeeds, see the note at the top
     */
    async start() {
        this.subscriber.on('messageBuffer', this.onBuffer);
        await this.subscribe();
    }

    async subscribe() {
        if (this.stopped || this.connected) {
            return;
        }
        try {
            await this.subscriber.subscribe(this.channel);
            if (this.stopped) {
                // stop() came while the subscribe was in flight
                await this.subscriber.unsubscribe(this.channel);
                return;
            }
        } catch (err) {
            if (this.stopped) {
                return;
            }
            this.failures++;
            // Once at a level an operator sees, then quietly until it works
            this.logger[this.failures === 1 ? 'error' : 'debug']({
                msg: 'Cannot subscribe to the cluster bus, running without it until it succeeds. Settings changes, listener and certificate reloads, live change events and account handoff hints do not reach the other instances meanwhile; a lone instance is not affected beyond this message. A Redis ACL user needs channel access: allchannels, or an & pattern covering the channel',
                channel: this.channel,
                retryInterval: this.retryInterval,
                err
            });
            this.scheduleRetry();
            return;
        }
        this.connected = true;
        if (this.failures) {
            this.logger.info({ msg: 'Cluster bus connected', channel: this.channel, attempts: this.failures + 1 });
        }
    }

    scheduleRetry() {
        // subscribe() never rejects: its one await is inside its try
        this.retryTimer = setTimeout(() => {
            this.retryTimer = null;
            this.subscribe();
        }, this.retryInterval);
        // The retry must not keep a process alive that is otherwise done
        this.retryTimer.unref();
    }

    /**
     * Broadcasts to every other instance. Never rejects: a lost broadcast is logged, the caller has
     * already acted locally. Nothing is sent while the bus is not connected, since publishing needs
     * the same channel access as subscribing and would fail the same way, once per broadcast; the
     * one error line from subscribe() says so
     */
    publish(type, data) {
        if (!this.connected) {
            return;
        }
        let payload;
        try {
            payload = msgpack.encode({ f: this.instanceId, t: type, d: data === undefined ? null : data });
        } catch (err) {
            this.logger.error({ msg: 'Failed to encode a cluster bus message', type, err });
            return;
        }
        this.publisher.publish(this.channel, payload).catch(err => this.logger.warn({ msg: 'Failed to publish a cluster bus message', type, err }));
    }

    async stop() {
        this.stopped = true;
        clearTimeout(this.retryTimer);
        this.retryTimer = null;
        this.subscriber.removeListener('messageBuffer', this.onBuffer);
        if (!this.connected) {
            return;
        }
        this.connected = false;
        try {
            await this.subscriber.unsubscribe(this.channel);
        } catch (err) {
            // the connection may already be closing
        }
    }
}

module.exports = { ClusterBus };
