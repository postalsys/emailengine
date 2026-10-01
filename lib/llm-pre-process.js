'use strict';

const { redis } = require('./db');
const msgpack = require('./msgpack');
const logger = require('./logger');
const { REDIS_PREFIX, AI_REQUEST_TIMEOUT } = require('./consts');
const { ALLOWED_HEADERS } = require('@postalsys/email-ai-tools');
const settings = require('./settings');
const { SubScript } = require('./sub-script');

// The last OpenAI failure, shown on the AI configuration page until a summary succeeds again
const OPENAI_ERROR_KEY = `${REDIS_PREFIX}:openai:error`;

// Headers the summary reads: the library's own whitelist, so what is fetched is what the model
// gets. Both sync paths fetch them for every new message while summaries are on, whatever the
// notifyHeaders setting asks for, and narrow them back out before the message is published. They
// are what the risk assessment is about: who the message claims to come from, whether the
// receiving server could verify that, and what conversation it belongs to
const SUMMARY_HEADERS = ALLOWED_HEADERS;

// What the sync paths fetch for the summary: the headers the model reads, and for a Microsoft
// mailbox the Received lines, which say whether Microsoft's unnamed authentication header is
// Microsoft's. Those never reach the model, the library keeps to its whitelist
const SUMMARY_FETCH_HEADERS = SUMMARY_HEADERS.concat(['received']);

/**
 * The headers to fetch for a mailbox while summaries are on
 *
 * @param {string|null} provider - As summaryProvider() names it
 * @returns {string[]}
 */
function summaryFetchHeaders(provider) {
    return provider === 'outlook' ? SUMMARY_FETCH_HEADERS : SUMMARY_HEADERS;
}

/**
 * Which provider's servers received the mail, as far as the authentication trust rule cares:
 * Google and Microsoft sign their Authentication-Results header in a known way. Told from what
 * the client learned at connect time (the Gmail capability, the host), never from the message
 *
 * @param {Object} client
 * @param {boolean} [client.isGmail] - The IMAP client's Gmail detection, or the API client's type
 * @param {boolean} [client.isOutlook]
 * @param {string} [client.host] - The IMAP host
 * @returns {string|null} 'gmail', 'outlook' or null
 */
function summaryProvider({ isGmail, isOutlook, host }) {
    host = (host || '').toLowerCase();
    if (isGmail || /(^|\.)(gmail|googlemail)\.com$/.test(host)) {
        return 'gmail';
    }
    if (isOutlook || /\b(office365|outlook|hotmail)\.(com|us)$/.test(host)) {
        return 'outlook';
    }
    return null;
}

/**
 * Which Authentication-Results header the summary may trust for a mailbox: the one written by
 * the server that received the message. Google signs its header with its own name and removes
 * any that arrives claiming it. Microsoft writes one without a name, which counts only when the
 * topmost Received line, the one Microsoft itself wrote, names a Microsoft host. Any other server
 * is trusted only by name, from the openAiTrustedAuthservIds setting: nothing about a message
 * tells whether its topmost header is the server's or the sender's, and a name a sender can guess
 * (the mailbox's domain, its MX) would let a forged pass through, so nothing is trusted by
 * default and the model treats the result as unknown
 *
 * @param {string|null} provider - As summaryProvider() names it
 * @param {Object} [headers] - The fetched headers, for the Received lines
 * @param {string[]} [configured] - The openAiTrustedAuthservIds setting
 * @returns {{trustedAuthservIds: string[], acceptUnnamedAuthentication?: boolean}}
 */
function authenticationTrust(provider, headers, configured) {
    if (provider === 'gmail') {
        return { trustedAuthservIds: ['mx.google.com'] };
    }
    if (provider === 'outlook') {
        const topmostReceived = [].concat((headers && headers.received) || [])[0] || '';
        return {
            trustedAuthservIds: ['protection.outlook.com', 'outlook.com'],
            acceptUnnamedAuthentication: /\b[a-z0-9.-]+\.(?:outlook|office365)\.(?:com|us)\b/i.test(topmostReceived)
        };
    }
    return { trustedAuthservIds: [].concat(configured || []) };
}

/**
 * The message as the summary library takes it: the decoded subject, sender and date EmailEngine
 * already parsed, every header the sync path fetched (the library keeps the ones it wants), the
 * attachment list without content, and the text parts. One shape for the sync path and for the
 * configuration page's test, so what the page shows is what a webhook gets
 *
 * @param {Object} messageData - Formatted message with its text parts
 * @returns {Object} Input for generateSummary()
 */
function buildSummaryInput(messageData) {
    const headers = messageData.headers || {};
    return {
        subject: messageData.subject,
        from: messageData.from,
        date: messageData.date,
        headers: Object.keys(headers).map(key => ({ key, value: [].concat(headers[key] || []) })),
        attachments: [].concat(messageData.attachments || []).map(attachment => ({ filename: attachment.filename, contentType: attachment.contentType })),
        text: messageData.text?.plain,
        html: messageData.text?.html
    };
}

class LLMPreProcessHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;

        this.handlerCache = null;
        this.handlerCacheV = 0;
    }

    getPreProcessLogKey() {
        return `${REDIS_PREFIX}llmpp:l`;
    }

    async getHandler() {
        const { generateEmailSummary, openAiAPIKey, openAiPreProcessingFn, openAiTrustedAuthservIds } = await settings.getMulti(
            'generateEmailSummary',
            'openAiAPIKey',
            'openAiPreProcessingFn',
            'openAiTrustedAuthservIds'
        );

        if (!generateEmailSummary || !openAiAPIKey) {
            return null;
        }

        const trustedAuthservIds = [].concat(openAiTrustedAuthservIds || []);

        // No filter script means every message goes. A script that does not compile means the
        // operator's intent is unknown, so nothing goes until it is fixed
        const script = (openAiPreProcessingFn || '').toString().trim();
        if (!script) {
            return { filterFn: null, trustedAuthservIds };
        }

        let compiledFn;
        try {
            compiledFn = SubScript.create(`llm-pre-process:filter`, script);
        } catch (err) {
            await this.storeLog('filter', null, err.stack);

            logger.error({ msg: 'Failed to compile LLM pre-processing script', component: 'llm-pre-process', type: 'filter', err });
            return null;
        }

        return {
            filterFn: async payload => {
                try {
                    return await compiledFn.exec(payload);
                } catch (err) {
                    await this.storeLog('filter', payload, err.stack);
                    logger.error({ msg: 'Failed to execute LLM pre-processing script', component: 'llm-pre-process', type: 'filter', err });
                    return null;
                }
            },
            trustedAuthservIds
        };
    }

    async getPreProcessHandler() {
        let v = await this.redis.hget(`${REDIS_PREFIX}settings`, 'openAiSettingsVersion');
        v = Number(v) || 0;
        if (v !== this.handlerCacheV) {
            // changes detected
            this.handlerCache = await this.getHandler();
            // mark the cache as current only after a successful rebuild, so a failure above
            // leaves it stale and the next call retries
            this.handlerCacheV = v;
        }
        return this.handlerCache;
    }

    async storeLog(type, payload, error) {
        const maxLogLines = 20;

        let logRow = msgpack.encode({
            type,
            payload,
            error,
            created: new Date().toISOString()
        });

        try {
            await redis.multi().rpush(this.getPreProcessLogKey(), logRow).ltrim(this.getPreProcessLogKey(), -maxLogLines, -1).exec();
        } catch (err) {
            logger.error({ msg: 'Failed to insert error log entries', component: 'llm-pre-process', err });
        }
    }

    async getErrorLog() {
        let logLines = await redis.lrangeBuffer(this.getPreProcessLogKey(), 0, -1);
        if (!Array.isArray(logLines)) {
            logLines = [].concat(logLines || []);
        }

        let logEntries = [];

        for (let line of logLines) {
            try {
                let entry = msgpack.decode(line);
                logEntries.unshift(entry);
            } catch (err) {
                logger.error({ msg: 'Failed to decode log line', component: 'llm-pre-process', entry: line && line.toString('base64'), err });
            }
        }

        return logEntries;
    }

    /**
     * Decides whether a message goes to the LLM: summaries have to be on, a key has to be set and
     * the operator's filter script, if there is one, has to accept the message. The script sees a
     * copy, so it cannot change what is announced
     * @param {Object} messageData - The message as the webhook would carry it
     * @returns {Promise<boolean>} True when the message should be summarized
     */
    async run(messageData) {
        let preProcessHandler = await this.getPreProcessHandler();
        if (!preProcessHandler) {
            return false;
        }

        // without a script there is nothing to show a copy to
        if (!preProcessHandler.filterFn) {
            return true;
        }

        return !!(await preProcessHandler.filterFn(structuredClone(messageData)));
    }

    /**
     * Asks the main thread for the AI summary of a message and attaches what the model returned
     * to the message in place, as it came. The request usage goes to the log; the main thread
     * counts it in the metrics. A failure is recorded for the AI configuration page and leaves
     * the message unenriched
     * @param {Object} messageData - Formatted message with its text parts, updated in place
     * @param {Object} env - Where the message lives
     * @param {Function} env.call - RPC to the main thread
     * @param {Object} env.redis - The connection's Redis client
     * @param {string} env.account - Account ID
     * @param {string|null} env.provider - As summaryProvider() names it, for the authentication trust rule
     * @param {Object} env.logger - Account-scoped logger
     */
    async summarize(messageData, { call, redis: client, account, provider, logger: log }) {
        try {
            const handler = await this.getPreProcessHandler();
            const { result, usage, signals } = await call({
                cmd: 'generateSummary',
                data: {
                    message: buildSummaryInput(messageData),
                    trust: authenticationTrust(provider, messageData.headers, handler && handler.trustedAuthservIds),
                    account
                },
                timeout: AI_REQUEST_TIMEOUT
            });

            messageData.summary = result;

            // usage is scalars only: the main thread strips the prompt text the verbose mode adds
            log.info({ msg: 'Generated email summary', id: messageData.id, messageId: messageData.messageId, usage, signals });

            await client.del(OPENAI_ERROR_KEY);
        } catch (err) {
            await client.set(
                OPENAI_ERROR_KEY,
                JSON.stringify({
                    message: err.message,
                    code: err.code,
                    statusCode: err.statusCode,
                    created: Date.now()
                })
            );
            log.error({ msg: 'Failed to fetch summary from OpenAI', err });
        }
    }
}

module.exports.llmPreProcess = new LLMPreProcessHandler({ redis });
module.exports.buildSummaryInput = buildSummaryInput;
module.exports.SUMMARY_HEADERS = SUMMARY_HEADERS;
module.exports.summaryFetchHeaders = summaryFetchHeaders;
module.exports.summaryProvider = summaryProvider;
module.exports.authenticationTrust = authenticationTrust;
