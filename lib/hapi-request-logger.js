'use strict';

// Request logging for the API server, in place of the hapi-pino plugin (which pulled a second pino
// major into the tree). It writes the same records hapi-pino did, because operators parse them:
//
// - every request gets `request.logger`, a child bound to the serialized request (`req`)
// - "[response] <method> <path> <status> (<ms>ms)" at info with `res` and `responseTime` when a
//   response is sent, "-" in place of the status when the client went away first
// - a request error event at error level with `err` and `tags`, its message as the line
// - server.log() and request.log() events with `tags` and `data`, at the most severe level named
//   among the tags (info when none is)
// - "server started" / "server stopped" carrying server.info
//
// The server is decorated with `server.logger`.

const { stdSerializers } = require('pino');

const LEVEL_TAGS = new Set(['trace', 'debug', 'info', 'warn', 'error', 'fatal']);

const SERIALIZERS = {
    req: stdSerializers.wrapRequestSerializer(stdSerializers.req),
    res: stdSerializers.wrapResponseSerializer(stdSerializers.res),
    err: stdSerializers.err
};

function logEvent(logger, event) {
    const tags = event.tags || [];

    let level = 'info';
    let highest = 0;
    for (const tag of tags) {
        if (LEVEL_TAGS.has(tag) && logger.levels.values[tag] > highest) {
            highest = logger.levels.values[tag];
            level = tag;
        }
    }

    logger[level]({ tags, data: event.data });
}

function getRequestLogger(logger, request) {
    if (!request.logger) {
        request.logger = logger.child({ req: request });
    }
    return request.logger;
}

module.exports = {
    name: 'request-logger',

    /**
     * @param {Object} server Hapi server
     * @param {Object} options
     * @param {Object} options.logger Pino logger to write through
     */
    register(server, options) {
        // Serializers the logger already carries win, the way hapi-pino merged them
        const logger = options.logger.child({}, { serializers: SERIALIZERS });

        server.decorate('server', 'logger', logger);

        server.ext('onRequest', (request, h) => {
            request.logger = logger.child({ req: request });
            return h.continue;
        });

        server.events.on('log', event => {
            if (event.error) {
                logger.error({ err: event.error, tags: event.tags });
            } else {
                logEvent(logger, event);
            }
        });

        server.events.on('request', (request, event, tags) => {
            // hapi's internal channel is noise apart from a malformed Accept-Encoding header
            if (event.channel === 'internal' && !tags['accept-encoding']) {
                return;
            }

            if (event.error) {
                getRequestLogger(logger, request).error({ tags: event.tags, err: event.error }, event.error.message);
            } else if (event.channel === 'app') {
                logEvent(getRequestLogger(logger, request), event);
            }
        });

        server.events.on('response', request => {
            const { info, raw } = request;
            const responseTime = (info.completed !== undefined ? info.completed : info.responded) - info.received;
            const status = raw.res.headersSent ? raw.res.statusCode : '-';

            getRequestLogger(logger, request).info(
                { res: raw.res, responseTime },
                `[response] ${request.method} ${request.path} ${status} (${responseTime}ms)`
            );
        });

        server.ext('onPostStart', async () => {
            logger.info(server.info, 'server started');
        });

        server.ext('onPostStop', async () => {
            logger.info(server.info, 'server stopped');
        });
    }
};
