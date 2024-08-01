'use strict';

const { parentPort } = require('worker_threads');
const crypto = require('crypto');
const logger = require('../logger');
const { webhooks: Webhooks } = require('../webhooks');
const { getESClient } = require('../document-store');
const { getThread } = require('../threads');
const settings = require('../settings');
const msgpack = require('msgpack5')();
const { templates } = require('../templates');
const { Gateway } = require('../gateway');
const os = require('os');
const punycode = require('punycode/');
const { inlineHtml, inlineText, htmlToText } = require('@postalsys/email-text-tools');
const uuid = require('uuid');
const { addTrackers } = require('../add-trackers');
const { getRawEmail } = require('../get-raw-email');
const { getTemplate } = require('@postalsys/templates');
const { deepEqual } = require('assert');

const {
    getSignedFormDataSync,
    getServiceSecret,
    convertDataUrisToAtachments,
    genBaseBoundary,
    getByteSize,
    readEnvValue,
    emitChangeEvent
} = require('../tools');

const {
    ACCOUNT_INITIALIZED_NOTIFY,
    REDIS_PREFIX,
    MESSAGE_NEW_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_UPDATED_NOTIFY,
    EMAIL_BOUNCE_NOTIFY,
    MAILBOX_DELETED_NOTIFY,
    DEFAULT_DELIVERY_ATTEMPTS,
    MIME_BOUNDARY_PREFIX,
    DEFAULT_DOWNLOAD_CHUNK_SIZE
} = require('../consts');

let pfStructuredClone = typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data));

const DOWNLOAD_CHUNK_SIZE = getByteSize(readEnvValue('EENGINE_CHUNK_SIZE')) || DEFAULT_DOWNLOAD_CHUNK_SIZE;

async function metricsMeta(meta, logger, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args,
            meta: meta || {}
        });
    } catch (err) {
        logger.error({ msg: 'Failed to post metrics to parent', err });
    }
}

class BaseClient {
    constructor(account, options) {
        this.account = account;

        this.options = options || {};

        this.cid = this.getRandomId();

        this.runIndex = this.options.runIndex;

        this.accountObject = this.options.accountObject;
        this.accountLogger = this.options.accountLogger;
        this.redis = this.options.redis;

        this.notifyQueue = this.options.notifyQueue;
        this.submitQueue = this.options.submitQueue;
        this.documentsQueue = this.options.documentsQueue;
        this.flowProducer = this.options.flowProducer;

        this.call = this.options.call;

        this.logger = this.getLogger();

        this.secret = this.options.secret;

        this.subconnections = [];
    }

    // stub methods

    async init() {
        return null;
    }

    async close() {
        return null;
    }

    async delete() {
        return null;
    }

    async resume() {
        return null;
    }

    async reconnect() {
        return null;
    }

    async subconnections() {
        return [];
    }

    async getQuota() {
        return false;
    }

    getRandomId() {
        let rid = BigInt('0x' + crypto.randomBytes(13).toString('hex')).toString(36);
        if (rid.length < 20) {
            rid = '0'.repeat(20 - rid.length) + rid;
        } else if (rid.length > 20) {
            rid = rid.substring(0, 20);
        }
        return rid;
    }

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getMailboxListKey() {
        return `${REDIS_PREFIX}ial:${this.account}`;
    }

    getMailboxHashKey() {
        return `${REDIS_PREFIX}iah:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${this.account}:g`;
    }

    getLoggedAccountsKey() {
        return `${REDIS_PREFIX}iaz:logged`;
    }

    currentState() {
        return 'connected';
    }

    getLogger() {
        this.mainLogger =
            this.options.logger ||
            logger.child({
                component: 'connection-client',
                account: this.account,
                cid: this.cid
            });

        let synteticLogger = {};
        let levels = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];
        for (let level of levels) {
            synteticLogger[level] = (...args) => {
                this.mainLogger[level](...args);

                if (this.accountLogger.enabled && args && args[0] && typeof args[0] === 'object') {
                    let entry = Object.assign({ level, t: Date.now(), cid: this.cid }, args[0]);
                    if (entry.err && typeof entry.err === 'object') {
                        let err = entry.err;
                        entry.err = {
                            stack: err.stack
                        };
                        // enumerable error fields
                        Object.keys(err).forEach(key => {
                            entry.err[key] = err[key];
                        });
                    }

                    this.accountLogger.log(entry);
                }
            };
        }

        synteticLogger.child = opts => this.mainLogger.child(opts);

        return synteticLogger;
    }

    async setStateVal() {
        let [[e1], [e2], [e3, prevVal], [e4, incrVal], [e5, stateVal]] = await this.redis
            .multi()
            .hSetExists(this.getAccountKey(), 'state', this.state)
            .hSetBigger(this.getAccountKey(), 'runIndex', this.runIndex.toString())
            .hget(this.getAccountKey(), `state:count:${this.state}`)
            .hIncrbyExists(this.getAccountKey(), `state:count:${this.state}`, 1)
            .hget(this.getAccountKey(), 'state')
            .exec();

        if (e1 || e2 || e3 || e4 || e5) {
            throw e1 || e2 || e3 || e4 || e5;
        }

        if (stateVal === 'connected' && incrVal === 1 && prevVal === '0') {
            // first connected event!
            await this.notify(false, ACCOUNT_INITIALIZED_NOTIFY, {
                initialized: true
            });
        }
    }

    async setErrorState(event, data) {
        let prevLastErrorState = await this.redis.hget(this.getAccountKey(), 'lastErrorState');
        if (prevLastErrorState) {
            try {
                prevLastErrorState = JSON.parse(prevLastErrorState);
            } catch (err) {
                // ignore
            }
        }

        this.state = event;
        await this.setStateVal();

        await this.redis.hSetExists(this.getAccountKey(), 'lastErrorState', JSON.stringify(data));

        await emitChangeEvent(this.logger, this.account, 'state', event, { error: data });

        if (data && Object.keys(data).length && prevLastErrorState) {
            // we have an error object, let's see if the error hasn't changed

            if (data.serverResponseCode && data.serverResponseCode === prevLastErrorState.serverResponseCode) {
                return false;
            }

            try {
                deepEqual(data, prevLastErrorState);
                // nothing changed
                return false;
            } catch (err) {
                // seems different, can emit
            }
        }

        return true;
    }

    async notify(mailbox, event, data, extraOpts) {
        extraOpts = extraOpts || {};
        const { skipWebhook, canSync = true } = extraOpts;

        metricsMeta({ account: this.account }, this.logger, 'events', 'inc', {
            event
        });

        switch (event) {
            case 'connectError':
            case 'authenticationError': {
                let shouldNotify = await this.setErrorState(event, data);

                if (!shouldNotify) {
                    // do not send a webhook as nothing really changed
                    return;
                }
                break;
            }
        }

        let serviceUrl = (await settings.get('serviceUrl')) || true;

        let payload = {
            serviceUrl,
            account: this.account,
            date: new Date().toISOString()
        };

        let path = (mailbox && mailbox.path) || (data && data.path);
        if (path) {
            payload.path = path;
        }

        if (mailbox && mailbox.listingEntry && mailbox.listingEntry.specialUse) {
            payload.specialUse = mailbox.listingEntry.specialUse;
        }

        if (event) {
            payload.event = event;
        }

        if (data) {
            payload.data = data;
        }

        let queueKeep = (await settings.get('queueKeep')) || true;

        let addDocumentQueueJob =
            canSync &&
            this.documentsQueue &&
            [MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY, EMAIL_BOUNCE_NOTIFY, MAILBOX_DELETED_NOTIFY].includes(event) &&
            (await settings.get('documentStoreEnabled'));

        if (addDocumentQueueJob && payload.data && event === MESSAGE_NEW_NOTIFY && !payload.data.threadId) {
            // Generate a thread ID for the email. This is also stored in ElasticSearch.
            const { index, client } = await getESClient(logger);
            try {
                if (client) {
                    let thread = await getThread(client, index, this.account, payload.data, logger);
                    if (thread) {
                        payload.data.threadId = thread;
                        logger.info({
                            msg: 'Provisioned thread ID for a message',
                            account: this.account,
                            message: payload.data.id,
                            threadId: payload.data.threadId
                        });
                    }
                }
            } catch (err) {
                if (logger.notifyError) {
                    logger.notifyError(err, event => {
                        event.setUser(this.account);
                        event.addMetadata('ee', {
                            index
                        });
                    });
                }
                logger.error({ msg: 'Failed to resolve thread', account: this.account, message: payload.data.id, err });
            }
        }

        const defaultJobOptions = {
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep,
            attempts: 10,
            backoff: {
                type: 'exponential',
                delay: 5000
            }
        };

        // use more attempts for ElasticSearch updates
        const documentJobOptions = Object.assign(pfStructuredClone(defaultJobOptions), { attempts: 16 });

        if (!skipWebhook && addDocumentQueueJob) {
            // add both jobs as a Flow

            let notifyPayload = await Webhooks.formatPayload(event, payload);

            const queueFlow = [
                {
                    name: event,
                    data: payload,
                    queueName: 'documents'
                }
            ];

            await Webhooks.pushToQueue(event, notifyPayload, {
                routesOnly: true,
                queueFlow
            });

            await this.flowProducer.add(
                {
                    name: event,
                    data: notifyPayload,
                    queueName: 'notify',
                    children: queueFlow
                },
                {
                    queuesOptions: {
                        notify: {
                            defaultJobOptions
                        },
                        documents: {
                            defaultJobOptions: documentJobOptions
                        }
                    }
                }
            );
        } else {
            // add to queues as normal jobs

            if (!skipWebhook) {
                await Webhooks.pushToQueue(event, await Webhooks.formatPayload(event, payload));
            }

            if (addDocumentQueueJob) {
                await this.documentsQueue.add(event, payload, documentJobOptions);
            }
        }
    }

    async queueMessage(data, meta) {
        let accountData = await this.accountObject.loadAccountData();

        let gatewayData;
        let gatewayObject;
        if (data.gateway) {
            gatewayObject = new Gateway({ gateway: data.gateway, redis: this.redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', messageId: data.messageId, gateway: data.gateway, err });
            }
        }

        if (!accountData.smtp && !accountData.oauth2 && !gatewayData) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        let licenseInfo = await this.call({ cmd: 'license' });

        // normal message
        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        // convert data uri images to attachments
        convertDataUrisToAtachments(data);

        if (data.template) {
            let templateData = await templates.get(data.template);
            if (!templateData || (templateData.account && templateData.account !== accountData.account)) {
                let err = new Error(`Requested template was not found [${data.template}]`);
                err.code = 'TemplateNotFound';
                err.statusCode = 404;
                throw err;
            }

            if (templateData.content && templateData.content.html && templateData.format) {
                data.render = data.render || {};
                data.render.format = templateData.format;
            }

            for (let key of Object.keys(templateData.content || {})) {
                data[key] = templateData.content[key];
            }

            delete data.template;
        }

        if (!data.mailMerge || !data.mailMerge.length) {
            return this.queueMessageEntry(data, meta, licenseInfo);
        }

        let mailMergeList = data.mailMerge;
        delete data.mailMerge;
        delete data.messageId;
        delete data.to;

        let messageProcessors = [];

        for (let mailMergeEntry of mailMergeList) {
            let messageCopy = pfStructuredClone(data);
            if (messageCopy.sendAt) {
                // date values do not survive JSON based copying
                messageCopy.sendAt = new Date(messageCopy.sendAt);
            }

            messageCopy.to = [mailMergeEntry.to];

            for (let key of ['messageId', 'sendAt']) {
                if (mailMergeEntry[key]) {
                    messageCopy[key] = mailMergeEntry[key];
                }
            }

            if (mailMergeEntry.params) {
                messageCopy.render = messageCopy.render || {};
                messageCopy.render.params = mailMergeEntry.params;
            }

            messageProcessors.push(this.queueMessageEntry(messageCopy, meta, licenseInfo));
        }

        let response = {
            mailMerge: []
        };

        let results = await Promise.allSettled(messageProcessors);
        for (let i = 0; i < mailMergeList.length; i++) {
            let mailMergeEntry = mailMergeList[i];
            let resultEntry = results[i];

            let result = Object.assign(
                {
                    success: resultEntry.status === 'fulfilled',
                    to: mailMergeEntry.to
                },
                resultEntry.status === 'fulfilled'
                    ? resultEntry.value.responseValue || {
                          messageId: resultEntry.value.messageId,
                          queueId: resultEntry.value.queueId,
                          sendAt: resultEntry.value.sendAt
                      }
                    : {
                          error: (resultEntry.reason && resultEntry.reason.message) || resultEntry.status,
                          code: (resultEntry.reason && resultEntry.reason.code) || 'SubmitFail',
                          statusCode: (resultEntry.reason && Number(resultEntry.reason.statusCode)) || null
                      }
            );

            response.mailMerge.push(result);
        }

        return response;
    }

    // placeholder
    async checkIMAPConnection() {
        return true;
    }

    async prepareRawMessage(data) {
        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        // convert data uri images to attachments
        convertDataUrisToAtachments(data);

        let accountData = await this.accountObject.loadAccountData();

        if (!data.from && data.reference?.action) {
            data.from = {
                name: accountData.name,
                address: accountData.email
            };
        }

        let inlineOptions = {
            locale: data.locale || accountData.locale || (await settings.get('locale')),
            tz: data.tz || accountData.tz || (await settings.get('timezone'))
        };

        delete data.locale;
        delete data.tz;

        let referencedMessage;
        let documentStoreUsed = false;

        // Resolve reference and update reference/in-reply-to headers
        if (data.reference && data.reference.message) {
            if (data.reference.documentStore && (await settings.get('documentStoreEnabled'))) {
                try {
                    referencedMessage = await this.accountObject.getMessage(data.reference.message, {
                        documentStore: true,
                        textType: '*'
                    });
                } catch (err) {
                    if (err.meta && err.meta.statusCode === 404) {
                        // not found
                    } else {
                        let error = new Error('ElasticSearch request failed');
                        error.info = {
                            response: (err.meta && err.meta.body) || err.message,
                            statusCode: err.meta && err.meta.statusCode
                        };
                        error.code = 'ESRequestError';
                        error.statusCode = (err.meta && err.meta.statusCode) || 500;
                        throw error;
                    }
                }
                documentStoreUsed = true;
            } else {
                let extendedData = data.reference.inline || data.reference.forwardAttachments;
                referencedMessage = await this.getMessage(data.reference.message, {
                    fields: !extendedData
                        ? {
                              uid: true,
                              flags: true,
                              envelope: true,
                              headers: ['references']
                          }
                        : false,
                    header: extendedData ? true : false,
                    textType: extendedData ? '*' : false
                });
            }

            if (!referencedMessage && !data.reference.ignoreMissing) {
                let err = new Error('Referenced message was not found');
                err.code = 'MessageNotFound';
                err.statusCode = 404;
                throw err;
            }

            if (referencedMessage) {
                let references = []
                    .concat(referencedMessage.messageId || [])
                    .concat(referencedMessage.inReplyTo || [])
                    .concat((referencedMessage.headers && referencedMessage.headers.references) || [])
                    .flatMap(line => line.split(/\s+/))
                    .map(ref => ref.trim())
                    .filter(ref => ref)
                    .map(ref => {
                        if (!/^</.test(ref)) {
                            ref = '<' + ref;
                        }
                        if (!/>$/.test(ref)) {
                            ref = ref + '>';
                        }
                        return ref;
                    });

                references = Array.from(new Set(references));
                if (references.length) {
                    if (!data.headers) {
                        data.headers = {};
                    }
                    data.headers.references = references.join(' ');
                }

                if (data.reference.action === 'reply' && referencedMessage.messageId) {
                    data.headers['in-reply-to'] = referencedMessage.messageId;
                }

                if (!data.subject && referencedMessage.subject) {
                    let subject = referencedMessage.subject;
                    let prefix;
                    switch (data.reference.action) {
                        case 'reply':
                            if (!/^Re:/i.test(subject)) {
                                prefix = 'Re';
                            }
                            break;
                        case 'forward':
                            if (!/^Fwd:/i.test(subject)) {
                                prefix = 'Fwd';
                            }
                            break;
                    }
                    data.subject = `${prefix ? prefix + ': ' : ''}${subject}`;
                }

                let cidAttachments = [];

                if (data.reference.inline) {
                    let inlineMessageData = {
                        text: referencedMessage.text && referencedMessage.text.plain,
                        html: referencedMessage.text && referencedMessage.text.html
                    };

                    for (let key of ['from', 'to', 'cc', 'bcc', 'date', 'subject']) {
                        inlineMessageData[key] = referencedMessage[key];
                    }

                    if (inlineMessageData.html) {
                        if (referencedMessage.attachments) {
                            // find all attachments that are referenced in the HTML
                            for (let attachment of referencedMessage.attachments) {
                                if (attachment.contentId && inlineMessageData.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                                    cidAttachments.push(attachment);
                                }
                            }
                        }

                        try {
                            data.html = inlineHtml(data.reference.action, data.html, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline HTML content', err });
                        }
                    }

                    if (data.text) {
                        try {
                            data.text = inlineText(data.reference.action, data.text, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline text content', err });
                        }
                    }
                }

                if (!data.to && data.reference.action === 'reply') {
                    data.to =
                        referencedMessage.replyTo && referencedMessage.replyTo.length
                            ? referencedMessage.replyTo
                            : referencedMessage.from
                            ? referencedMessage.from
                            : false;
                }

                let attachmentsToDownload;

                if (
                    data.reference.action === 'forward' &&
                    data.reference.forwardAttachments &&
                    referencedMessage.attachments &&
                    referencedMessage.attachments.length
                ) {
                    // download all
                    attachmentsToDownload = referencedMessage.attachments;
                } else if (cidAttachments.length) {
                    // download referenced attachments
                    attachmentsToDownload = cidAttachments;
                }

                if (attachmentsToDownload && attachmentsToDownload.length) {
                    this.checkIMAPConnection();

                    this.logger.info({
                        msg: 'Fetching attachments from the referenced email',
                        attachments: attachmentsToDownload.map(a => ({ id: a.id, hasContent: !!a.content }))
                    });

                    // fetch and add attachments to the message
                    if (!data.attachments) {
                        data.attachments = [];
                    }
                    for (let attachment of attachmentsToDownload) {
                        let content;
                        if (attachment.content) {
                            // use local cache
                            content = Buffer.from(attachment.content, 'base64');
                            this.logger.trace({ msg: 'Using cached email content', attachment: attachment.id, size: content.length });
                        } else {
                            // fetch from IMAP
                            content = await this.getAttachmentContent(attachment.id, {
                                chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024)
                            });
                        }
                        if (!content) {
                            // skip missing?
                            continue;
                        }
                        data.attachments.push({
                            filename: attachment.filename,
                            content,
                            contentType: attachment.contentType,
                            contentDisposition: attachment.inline ? 'inline' : 'attachment',
                            cid: attachment.contentId || null
                        });
                    }
                }
            }
        }

        // resolve referenced attachments
        for (let attachment of data.attachments || []) {
            if (attachment.reference && !attachment.content) {
                this.checkIMAPConnection();

                let content = await this.getAttachmentContent(attachment.reference, {
                    chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024)
                });
                if (!content) {
                    let error = new Error('Referenced attachment was not found');
                    error.code = 'ReferenceNotFound';
                    error.statusCode = 404;
                    throw error;
                }

                attachment.content = content;
            }
        }

        data.disableUrlAccess = true;
        data.disableFileAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();
        data.newline = '\r\n';

        if (data.internalDate && !data.date) {
            // Update Date: header as well
            data.date = new Date(data.internalDate);
        }

        let { raw, messageId } = await getRawEmail(data);

        return { raw, messageId, documentStoreUsed, referencedMessage };
    }

    async queueMessageEntry(data, meta, licenseInfo) {
        let accountData = await this.accountObject.loadAccountData();

        // normal message
        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        let baseUrl = data.baseUrl || (await settings.get('serviceUrl')) || null;

        let context = {
            params: (data.render && data.render.params) || {},
            account: {
                name: accountData.name,
                email: accountData.email
            },
            service: {
                url: baseUrl
            }
        };

        if (!data.from) {
            data.from = {
                name: accountData.name,
                address: accountData.email,
                _default: true
            };
        }

        if (baseUrl && data.listId && data.to && data.to.length === 1 && data.to[0].address) {
            // check if not already blocked

            let blockData;

            try {
                blockData = await this.redis.hget(`${REDIS_PREFIX}lists:unsub:entries:${data.listId}`, data.to[0].address.toLowerCase().trim());
                blockData = JSON.parse(blockData);
            } catch (err) {
                blockData = false;
            }

            if (blockData) {
                return {
                    responseValue: {
                        skipped: {
                            reason: blockData.reason,
                            listId: data.listId
                        }
                    }
                };
            }

            if (!data.headers) {
                data.headers = {};
            }

            let baseDomain;
            try {
                baseDomain = (new URL(baseUrl).hostname || '').toLowerCase().trim();
            } catch (err) {
                // ignore error
            }
            baseDomain = baseDomain || (os.hostname() || '').toLowerCase().trim() || 'localhost';

            if (baseDomain) {
                let unsubscribeUrlObj = new URL('/unsubscribe', baseUrl);

                const serviceSecret = await getServiceSecret();

                let fromDomain = ((data.from && data.from.address) || '').split('@').pop().trim().toLowerCase() || baseDomain;
                try {
                    fromDomain = punycode.toASCII(fromDomain);
                } catch (err) {
                    // ignore
                }

                data.headers['List-ID'] = `<${data.listId}.${baseDomain}>`;

                if (!data.messageId) {
                    data.messageId = `<${uuid.v4()}@${fromDomain}>`;
                }

                let { data: signedData, signature } = getSignedFormDataSync(
                    serviceSecret,
                    {
                        act: 'unsub',
                        acc: accountData.account,
                        list: data.listId,
                        rcpt: data.to[0].address,
                        msg: data.messageId
                    },
                    true
                );

                unsubscribeUrlObj.searchParams.append('data', signedData);
                if (signature) {
                    unsubscribeUrlObj.searchParams.append('sig', signature);
                }

                context.rcpt = Object.assign({}, data.to[0], { unsubscribeUrl: unsubscribeUrlObj.href });

                data.headers['List-Unsubscribe'] = `<${context.rcpt.unsubscribeUrl}>`;
                data.headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
            }
        }

        for (let key of ['subject', 'html', 'text', 'previewText']) {
            if (data.render || data.listId) {
                data[key] = this.render(data[key], context, key, data.render && data.render.format);
            }
        }

        delete data.render;

        let inlineOptions = {
            locale: data.locale || accountData.locale || (await settings.get('locale')),
            tz: data.tz || accountData.tz || (await settings.get('timezone'))
        };

        delete data.locale;
        delete data.tz;

        if (data.html && !data.text) {
            try {
                data.text = htmlToText(data.html);
            } catch (err) {
                this.logger.error({ msg: 'Failed to generate plaintext content from html', err });
            }
        }

        let referencedMessage;
        let documentStoreUsed = false;

        // Resolve reference and update reference/in-reply-to headers
        if (data.reference && data.reference.message) {
            if (data.reference.documentStore && (await settings.get('documentStoreEnabled'))) {
                try {
                    referencedMessage = await this.accountObject.getMessage(data.reference.message, {
                        documentStore: true,
                        textType: '*'
                    });
                } catch (err) {
                    if (err.meta && err.meta.statusCode === 404) {
                        // not found
                    } else {
                        let error = new Error('ElasticSearch request failed');
                        error.info = {
                            response: (err.meta && err.meta.body) || err.message,
                            statusCode: err.meta && err.meta.statusCode
                        };
                        error.code = 'ESRequestError';
                        error.statusCode = (err.meta && err.meta.statusCode) || 500;
                        throw error;
                    }
                }
                documentStoreUsed = true;
            } else {
                this.checkIMAPConnection();

                let extendedData = data.reference.inline || data.reference.forwardAttachments;
                referencedMessage = await this.getMessage(data.reference.message, {
                    fields: !extendedData
                        ? {
                              uid: true,
                              flags: true,
                              envelope: true,
                              headers: ['references']
                          }
                        : false,
                    header: extendedData ? true : false,
                    textType: extendedData ? '*' : false
                });
            }

            if (!referencedMessage && !data.reference.ignoreMissing) {
                let error = new Error('Referenced message was not found');
                error.code = 'ReferenceNotFound';
                error.statusCode = 404;
                throw error;
            }

            if (referencedMessage) {
                let references = []
                    .concat(referencedMessage.messageId || [])
                    .concat(referencedMessage.inReplyTo || [])
                    .concat((referencedMessage.headers && referencedMessage.headers.references) || [])
                    .flatMap(line => line.split(/\s+/))
                    .map(ref => ref.trim())
                    .filter(ref => ref)
                    .map(ref => {
                        if (!/^</.test(ref)) {
                            ref = '<' + ref;
                        }
                        if (!/>$/.test(ref)) {
                            ref = ref + '>';
                        }
                        return ref;
                    });

                references = Array.from(new Set(references));
                if (references.length) {
                    if (!data.headers) {
                        data.headers = {};
                    }
                    data.headers.references = references.join(' ');
                }

                if (data.reference.action === 'reply' && referencedMessage.messageId) {
                    data.headers['in-reply-to'] = referencedMessage.messageId;
                }

                let referenceFlags = ['\\Answered'].concat(data.reference.action === 'forward' ? '$Forwarded' : []);
                if (!referencedMessage.flags || !referencedMessage.flags.length || !referenceFlags.some(flag => referencedMessage.flags.includes(flag))) {
                    data.reference.update = true;
                }

                if (!data.subject && referencedMessage.subject) {
                    let subject = referencedMessage.subject;
                    let prefix;
                    switch (data.reference.action) {
                        case 'reply':
                            if (!/^Re:/i.test(subject)) {
                                prefix = 'Re';
                            }
                            break;
                        case 'forward':
                            if (!/^Fwd:/i.test(subject)) {
                                prefix = 'Fwd';
                            }
                            break;
                    }
                    data.subject = `${prefix ? prefix + ': ' : ''}${subject}`;
                }

                let cidAttachments = [];

                if (data.reference.inline) {
                    let inlineMessageData = {
                        text: referencedMessage.text && referencedMessage.text.plain,
                        html: referencedMessage.text && referencedMessage.text.html
                    };

                    for (let key of ['from', 'to', 'cc', 'bcc', 'date', 'subject']) {
                        inlineMessageData[key] = referencedMessage[key];
                    }

                    if (inlineMessageData.html) {
                        if (referencedMessage.attachments) {
                            // find all attachments that are referenced in the HTML
                            for (let attachment of referencedMessage.attachments) {
                                if (attachment.contentId && inlineMessageData.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                                    cidAttachments.push(attachment);
                                }
                            }
                        }

                        try {
                            data.html = inlineHtml(data.reference.action, data.html, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline HTML content', err });
                        }
                    }

                    if (data.text) {
                        try {
                            data.text = inlineText(data.reference.action, data.text, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline text content', err });
                        }
                    }
                }

                if (!data.to && data.reference.action === 'reply') {
                    data.to =
                        referencedMessage.replyTo && referencedMessage.replyTo.length
                            ? referencedMessage.replyTo
                            : referencedMessage.from
                            ? referencedMessage.from
                            : false;
                }

                let attachmentsToDownload;

                if (
                    data.reference.action === 'forward' &&
                    data.reference.forwardAttachments &&
                    referencedMessage.attachments &&
                    referencedMessage.attachments.length
                ) {
                    // download all
                    attachmentsToDownload = referencedMessage.attachments;
                } else if (cidAttachments.length) {
                    // download referenced attachments
                    attachmentsToDownload = cidAttachments;
                }

                if (attachmentsToDownload && attachmentsToDownload.length) {
                    this.checkIMAPConnection();

                    this.logger.info({
                        msg: 'Fetching attachments from the referenced email',
                        attachments: attachmentsToDownload.map(a => ({ id: a.id, hasContent: !!a.content }))
                    });

                    // fetch and add attachments to the message
                    if (!data.attachments) {
                        data.attachments = [];
                    }
                    for (let attachment of attachmentsToDownload) {
                        let content;
                        if (attachment.content) {
                            // use local cache
                            content = Buffer.from(attachment.content, 'base64');
                            this.logger.trace({ msg: 'Using cached email content', attachment: attachment.id, size: content.length });
                        } else {
                            // fetch from IMAP
                            content = await this.getAttachmentContent(attachment.id, {
                                chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024)
                            });
                        }
                        if (!content) {
                            // skip missing?
                            continue;
                        }
                        data.attachments.push({
                            filename: attachment.filename,
                            content,
                            contentType: attachment.contentType,
                            contentDisposition: attachment.inline ? 'inline' : 'attachment',
                            cid: attachment.contentId || null
                        });
                    }
                }
            }
        }

        // resolve referenced attachments
        for (let attachment of data.attachments || []) {
            if (attachment.reference && !attachment.content) {
                this.checkIMAPConnection();

                let content = await this.getAttachmentContent(attachment.reference, {
                    chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024)
                });

                if (!content) {
                    let error = new Error('Referenced attachment was not found');
                    error.code = 'ReferenceNotFound';
                    error.statusCode = 404;
                    throw error;
                }

                attachment.content = content;
            }
        }

        let { raw, hasBcc, envelope, subject, messageId, sendAt, deliveryAttempts, trackingEnabled, gateway } = await getRawEmail(data, licenseInfo);

        if (data.dryRun) {
            let response = {
                response: 'Dry run',
                messageId
            };

            if (data.reference && data.reference.message) {
                response.reference = {
                    message: data.reference.message,
                    documentStore: documentStoreUsed,
                    success: referencedMessage ? true : false
                };

                if (!referencedMessage) {
                    response.reference.error = 'Referenced message was not found';
                }
            }

            response.preview = raw.toString('base64');

            return response;
        }

        let gatewayData;
        if (gateway) {
            let gatewayObject = new Gateway({ gateway, redis: this.redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', envelope, messageId, gateway, err });
            }
        }

        if (!accountData.smtp && !accountData.oauth2 && !gatewayData) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        if (typeof trackingEnabled !== 'boolean') {
            trackingEnabled = (await settings.get('trackSentMessages')) || false;
        }

        if (raw && trackingEnabled && baseUrl) {
            // add open and click tracking
            raw = await addTrackers(raw, accountData.account, messageId, baseUrl);
        }

        let now = new Date();

        //queue for later

        // Use timestamp in the ID to make sure that jobs are ordered by send time
        let timeBuf = Buffer.allocUnsafe(8);

        timeBuf.writeBigInt64BE(BigInt((sendAt && sendAt.getTime()) || Date.now()), 0);

        let queueId = Buffer.concat([timeBuf.subarray(2), crypto.randomBytes(4)])
            .toString('hex')
            .substr(1);

        let msgEntry = msgpack.encode({
            queueId,
            gateway: gatewayData && gatewayData.gateway,
            hasBcc,
            envelope,
            messageId,
            reference: data.reference || {},
            sendAt: (sendAt && sendAt.getTime()) || false,
            created: now.getTime(),
            copy: data.copy,
            sentMailPath: data.sentMailPath,
            feedbackKey: data.feedbackKey || null,
            dsn: data.dsn || null,
            proxy: data.proxy || null,
            localAddress: data.localAddress || null,
            raw
        });

        await this.redis.hsetBuffer(`${REDIS_PREFIX}iaq:${this.account}`, queueId, msgEntry);

        let queueKeep = (await settings.get('queueKeep')) || true;

        let defaultDeliveryAttempts = await settings.get('deliveryAttempts');
        if (typeof defaultDeliveryAttempts !== 'number') {
            defaultDeliveryAttempts = DEFAULT_DELIVERY_ATTEMPTS;
        }

        let jobData = Object.assign({}, meta || {}, {
            account: this.account,
            queueId,
            gateway: (gatewayData && gatewayData.gateway) || null,
            messageId,
            envelope,
            subject,
            proxy: data.proxy,
            localAddress: data.localAddress,
            created: now.getTime()
        });

        let queueName = 'queued';
        let jobOpts = {
            jobId: queueId,
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep,
            attempts: typeof deliveryAttempts === 'number' ? deliveryAttempts : defaultDeliveryAttempts,
            backoff: {
                type: 'exponential',
                delay: 5000
            }
        };

        if (sendAt && sendAt > now) {
            queueName = 'delayed';
            jobOpts.delay = sendAt.getTime() - now.getTime();
        }

        let job = await this.submitQueue.add(queueName, jobData, jobOpts);

        try {
            await job.updateProgress({
                status: 'queued'
            });
        } catch (err) {
            // ignore
        }

        this.logger.info({ msg: 'Message queued for delivery', envelope, messageId, sendAt: (sendAt || now).toISOString(), queueId, job: job.id });

        let response = {
            response: 'Queued for delivery',
            messageId,
            sendAt: (sendAt || now).toISOString(),
            queueId
        };

        if (data.reference && data.reference.message) {
            response.reference = {
                message: data.reference.message,
                documentStore: documentStoreUsed,
                success: referencedMessage ? true : false
            };

            if (!referencedMessage) {
                response.reference.error = 'Referenced message was not found';
            }
        }

        return response;
    }

    render(template, data, key, renderFormat) {
        let format;

        switch (key) {
            case 'subject':
            case 'text': {
                format = 'plain';
                break;
            }

            case 'html': {
                format = renderFormat ? renderFormat : 'html';
                break;
            }

            case 'previewText':
            default: {
                format = 'html';
                break;
            }
        }

        try {
            const compiledTemplate = getTemplate({
                format,
                template
            });

            return compiledTemplate(data);
        } catch (err) {
            logger.error({ msg: `Failed rendering ${key} template`, err });
            let error = new Error(`Failed rendering ${key} template`);
            error.code = err.code || 'SubmitFail';
            error.statusCode = 422;
            throw error;
        }
    }

    isAutoreply(messageInfo) {
        if (/^(auto:|Out of Office|OOF:|OOO:)/i.test(messageInfo.subject) && messageInfo.inReplyTo) {
            return true;
        }

        if (!messageInfo.headers) {
            return false;
        }

        if (messageInfo.headers.precedence && messageInfo.headers.precedence.some(e => /auto[_-]?reply/.test(e))) {
            return true;
        }

        if (messageInfo.headers['auto-submitted'] && messageInfo.headers['auto-submitted'].some(e => /auto[_-]?replied/.test(e))) {
            return true;
        }

        for (let headerKey of ['x-autoresponder', 'x-autorespond', 'x-autoreply']) {
            if (messageInfo.headers[headerKey] && messageInfo.headers[headerKey].length) {
                return true;
            }
        }

        return false;
    }
}

module.exports = { BaseClient };
