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

const msgpack = require('../msgpack');

class ClusterBus {
    /**
     * @param {Object} opts
     * @param {Object} opts.publisher - ioredis client used for PUBLISH
     * @param {Object} opts.subscriber - Dedicated ioredis client, put into subscriber mode
     * @param {string} opts.channel
     * @param {string} opts.instanceId
     * @param {Object} opts.logger
     * @param {Function} opts.onMessage - (type, data, from) for every message of another instance
     */
    constructor({ publisher, subscriber, channel, instanceId, logger, onMessage }) {
        this.publisher = publisher;
        this.subscriber = subscriber;
        this.channel = channel;
        this.instanceId = instanceId;
        this.logger = logger;
        this.onMessage = onMessage;
        this.published = 0;
        this.received = 0;

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
            this.received++;
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

    async start() {
        this.subscriber.on('messageBuffer', this.onBuffer);
        await this.subscriber.subscribe(this.channel);
    }

    /**
     * Broadcasts to every other instance. Never rejects: a lost broadcast is logged, the caller has
     * already acted locally
     */
    publish(type, data) {
        let payload;
        try {
            payload = msgpack.encode({ f: this.instanceId, t: type, d: data === undefined ? null : data });
        } catch (err) {
            this.logger.error({ msg: 'Failed to encode a cluster bus message', type, err });
            return;
        }
        this.published++;
        this.publisher.publish(this.channel, payload).catch(err => this.logger.warn({ msg: 'Failed to publish a cluster bus message', type, err }));
    }

    async stop() {
        this.subscriber.removeListener('messageBuffer', this.onBuffer);
        try {
            await this.subscriber.unsubscribe(this.channel);
        } catch (err) {
            // the connection may already be closing
        }
    }
}

module.exports = { ClusterBus };
