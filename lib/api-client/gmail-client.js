'use strict';

const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const msgpack = require('msgpack5')();
const logger = require('../logger');
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');
const he = require('he');

const { REDIS_PREFIX } = require('../consts');

const fs = require('fs');

const GMAIL_API_BASE = 'https://gmail.googleapis.com';
const LIST_BATCH_SIZE = 10; // how many listing requests to run at the same time

const SKIP_LABELS = ['UNREAD', 'STARRED', 'IMPORTANT', 'CHAT', 'CATEGORY_PERSONAL'];

const SYSTEM_LABELS = {
    SENT: '\\Sent',
    INBOX: '\\Inbox',
    TRASH: '\\Trash',
    DRAFT: '\\Drafts',
    SPAM: '\\Junk',
    IMPORTANT: '\\Important'
};

const SYSTEM_NAMES = {
    SENT: 'Sent ',
    INBOX: 'Inbox',
    TRASH: 'Trash',
    DRAFT: 'Drafts',
    SPAM: 'Spam',
    CATEGORY_FORUMS: 'Forums',
    CATEGORY_UPDATES: 'Updates',
    CATEGORY_SOCIAL: 'Social',
    CATEGORY_PROMOTIONS: 'Promotions'
};

/*

✅ listMessages
  ❌ paging - not implemented
✅ getText
✅ getMessage
case 'updateMessage':
case 'updateMessages':
✅ listMailboxes
case 'moveMessage':
case 'moveMessages':
✅ deleteMessage - no force option
case 'deleteMessages':
✅ getRawMessage
⭕️ getQuota - not supported
case 'createMailbox':
case 'renameMailbox':
case 'deleteMailbox':
✅ getAttachment
case 'submitMessage':
case 'queueMessage':
case 'uploadMessage':
⭕️ subconnections - not supported

*/

class GmailClient {
    constructor(account, options) {
        this.account = account;
        this.options = options || {};

        this.accountLogger = options.accountLogger;
        this.redis = options.redis;
        this.logger = options.logger || logger;

        this.subconnections = [];
    }

    async init() {
        // No-op
    }

    async delete() {
        // No-op
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

    async getAccount() {
        if (this.accountObject) {
            return this.accountObject;
        }
        this.accountObject = new Account({ redis: this.redis, account: this.account, secret: await getSecret() });
        return this.accountObject;
    }

    async getToken() {
        const tokenData = await this.accountObject.getActiveAccessTokenData();
        return tokenData.accessToken;
    }

    async getClient() {
        if (this.oAuth2Client) {
            return this.oAuth2Client;
        }
        let accountData = await this.accountObject.loadAccountData(this.account, false);
        this.oAuth2Client = await oauth2Apps.getClient(accountData.oauth2.provider, {
            logger: this.logger,
            logRaw: this.options.logRaw
        });
        return this.oAuth2Client;
    }

    async prepare() {
        await this.getAccount();
        await this.getClient();
    }

    // Treat Quota request as unsupported by mail server
    async getQuota() {
        return false;
    }

    async listMailboxes(options) {
        console.log('LIST MAILBOXES', options);
        await this.prepare();
        console.log(1);
        const accessToken = await this.getToken();
        console.log(2, accessToken);
        let labelsResult = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/labels`);
        console.log(3, labelsResult);
        let labels = labelsResult.labels.filter(label => !SKIP_LABELS.includes(label.id));

        let resultLabels;
        if (options && options.counters) {
            resultLabels = [];
            for (let label of labels) {
                let labelResult = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/labels/${label.id}`);
                resultLabels.push(labelResult);
            }
        } else {
            resultLabels = labels;
        }

        console.log(3, resultLabels);

        let mailboxes = resultLabels
            .map(label => {
                let pathParts = label.name.split('/');
                let name = pathParts.pop();
                let parentPath = pathParts.join('/');

                let entry = {
                    id: label.id,
                    path: label.name,
                    delimiter: '/',
                    parentPath,
                    name: label.type === 'system' && SYSTEM_NAMES[name] ? SYSTEM_NAMES[name] : name,
                    listed: true,
                    subscribed: true
                };

                if (label.type === 'system' && SYSTEM_LABELS.hasOwnProperty(label.id)) {
                    entry.specialUse = SYSTEM_LABELS[label.id];
                    entry.specialUseSource = 'extension';
                }

                if (label.type === 'system' && /^CATEGORY/.test(label.id)) {
                    entry.specialUse =
                        '\\Category' +
                        label.id
                            .split('_')
                            .pop()
                            .toLowerCase()
                            .replace(/^./, c => c.toUpperCase());
                    entry.specialUseSource = 'name';
                }

                if (!isNaN(label.messagesTotal)) {
                    entry.status = {
                        messages: label.messagesTotal,
                        unseen: label.messagesUnread
                    };
                }

                return entry;
            })
            .sort((a, b) => {
                if (a.path === 'INBOX') {
                    return -1;
                } else if (b.path === 'INBOX') {
                    return 1;
                }

                if (/^CATEGORY/.test(a.id) && /^CATEGORY/.test(b.id)) {
                    return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
                } else if (/^CATEGORY/.test(a.id)) {
                    return -1;
                } else if (/^CATEGORY/.test(b.id)) {
                    return 1;
                }

                if (a.specialUse && !b.specialUse) {
                    return -1;
                } else if (!a.specialUse && b.specialUse) {
                    return 1;
                }

                return a.path.toLowerCase().localeCompare(b.path.toLowerCase());
            });
        console.log(555, mailboxes);

        return mailboxes;
    }

    getEnvelope(messageData) {
        let envelope = {};
        for (let key of ['from', 'to', 'cc', 'bcc', 'sender', 'reply-to']) {
            for (let header of messageData.payload.headers.filter(header => header.name.toLowerCase() === key)) {
                let parsed = addressparser(header.value, { flatten: true });

                let envelopekey = key.toLowerCase().replace(/-(.)/g, (o, c) => c.toUpperCase());

                envelope[envelopekey] = [].concat(envelope[envelopekey] || []).concat(parsed || []);
            }
        }

        envelope.messageId = messageData.payload.headers.find(header => header.name.toLowerCase() === 'message-id')?.value?.trim();
        envelope.inReplyTo = messageData.payload.headers.find(header => header.name.toLowerCase() === 'in-reply-to')?.value?.trim();

        return envelope;
    }

    getAttachmentList(messageData, options) {
        options = options || {};

        let encodedTextSize = {};
        const attachments = [];
        const textParts = [[], [], []];
        const textContents = [[], [], []];

        let walk = (node, isRelated) => {
            if (node.mimeType === 'multipart/related') {
                isRelated = true;
            }

            const dispositionHeader = node.headers?.find(header => /^content-disposition$/i.test(header.name))?.value || '';
            const contentTypeHeader = node.headers?.find(header => /^content-type$/i.test(header.name))?.value || '';
            const contentId = (node.headers?.find(header => /^content-id$/i.test(header.name))?.value || '').toString().trim();

            let disposition;
            if (dispositionHeader) {
                disposition = libmime.parseHeaderValue(dispositionHeader);
                disposition.value = (disposition.value || '').toString().trim().toLowerCase();
            }

            let contentType;
            if (contentTypeHeader) {
                contentType = libmime.parseHeaderValue(contentTypeHeader);
                contentType.value = (contentType.value || '').toString().trim().toLowerCase();
            }

            if (!/^multipart\//.test(node.mimeType)) {
                if (node.body.attachmentId) {
                    const attachmentIdProps = [messageData.id, node.mimeType || null, disposition?.value || null, node.filename || null];

                    const attachment = {
                        // append body part nr to message id
                        id: `${msgpack.encode(attachmentIdProps).toString('base64url')}.${node.body.attachmentId}`,
                        contentType: node.mimeType,
                        encodedSize: node.body.size,

                        embedded: isRelated,
                        inline: disposition?.value === 'inline' || (!disposition && isRelated)
                    };

                    if (node.filename) {
                        attachment.filename = node.filename;
                    }

                    if (contentId) {
                        attachment.contentId = contentId.replace(/^<*/, '<').replace(/>*$/, '>');
                    }

                    if (typeof contentType?.params?.method === 'string') {
                        attachment.method = contentType.params.method;
                    }

                    attachments.push(attachment);
                } else if ((!disposition || disposition.value === 'inline') && /^text\/(plain|html)/.test(node.mimeType)) {
                    let type = node.mimeType.substr(5);
                    if (!encodedTextSize[type]) {
                        encodedTextSize[type] = 0;
                    }
                    encodedTextSize[type] += node.body.size;
                    switch (type) {
                        case 'plain':
                            textParts[0].push(node.partId);
                            if ([type, '*'].includes(options.textType)) {
                                textContents[0].push(Buffer.from(node.body.data, 'base64'));
                            }
                            break;
                        case 'html':
                            textParts[1].push(node.partId);
                            if ([type, '*'].includes(options.textType)) {
                                textContents[1].push(Buffer.from(node.body.data, 'base64'));
                            }
                            break;
                        default:
                            textParts[2].push(node.partId);
                            if (['*'].includes(options.textType)) {
                                textContents[0].push(Buffer.from(node.body.data, 'base64'));
                            }
                            break;
                    }
                }
            }

            if (node.parts) {
                node.parts.forEach(childNode => walk(childNode, isRelated));
            }
        };

        walk(messageData.payload, false);

        for (let i = 0; i < textContents.length; i++) {
            textContents[i] = textContents[i].length ? Buffer.concat(textContents[i]) : null;
        }

        return {
            attachments,
            textId: msgpack.encode([messageData.id, textParts]).toString('base64url'),
            encodedTextSize,
            textContents
        };
    }

    formatMessage(messageData, options) {
        let { extended, path, textType } = options || {};

        let date = messageData.internalDate && !isNaN(messageData.internalDate) ? new Date(Number(messageData.internalDate)) : undefined;
        if (date.toString() === 'Invalid Date') {
            date = undefined;
        }

        let flags = [];
        if (!messageData.labelIds.includes('UNREAD')) {
            flags.push('\\Seen');
        }

        if (messageData.labelIds.includes('STARRED')) {
            flags.push('\\Flagged');
        }

        if (messageData.labelIds.includes('DRAFT')) {
            flags.push('\\Draft');
        }

        let labels = [];
        let category;

        for (let label of messageData.labelIds) {
            if (SKIP_LABELS.includes(label)) {
                continue;
            }
            if (SYSTEM_LABELS.hasOwnProperty(label)) {
                labels.push(SYSTEM_LABELS[label]);
            } else if (SYSTEM_NAMES.hasOwnProperty(label) && /^CATEGORY/.test(label)) {
                // ignore
                category = label.split('_').pop().toLowerCase();
            } else {
                labels.push(label);
            }
        }
        if (!category && labels.includes('\\Inbox')) {
            category = 'primary';
        }

        let envelope = this.getEnvelope(messageData);

        let headers = {};
        for (let header of messageData.payload.headers) {
            let key = header.name.toLowerCase();
            if (!headers[key]) {
                headers[key] = [header.value];
            } else {
                headers[key].push(header.value);
            }
        }

        const { attachments, textId, encodedTextSize, textContents } = this.getAttachmentList(messageData, { textType });

        const result = {
            id: messageData.id,
            uid: messageData.uid,

            path: (extended && path) || undefined,

            emailId: messageData.id || undefined,
            threadId: messageData.threadId || undefined,

            date: date ? date.toISOString() : undefined,

            flags,
            labels,
            category,

            unseen: !flags.includes('\\Seen') ? true : undefined,
            flagged: flags.includes('\\Flagged') ? true : undefined,
            draft: flags.includes('\\Draft') ? true : undefined,

            size: messageData.sizeEstimate,
            subject: messageData.payload.headers.find(header => header.name.toLowerCase() === 'subject')?.value || undefined,
            from: envelope.from && envelope.from[0] ? envelope.from[0] : undefined,

            replyTo: envelope.replyTo && envelope.replyTo.length ? envelope.replyTo : undefined,
            sender: extended && envelope.sender && envelope.sender[0] ? envelope.sender[0] : undefined,

            to: envelope.to && envelope.to.length ? envelope.to : undefined,
            cc: envelope.cc && envelope.cc.length ? envelope.cc : undefined,

            bcc: extended && envelope.bcc && envelope.bcc.length ? envelope.bcc : undefined,

            attachments: attachments && attachments.length ? attachments : undefined,
            messageId: (envelope.messageId && envelope.messageId.toString().trim()) || undefined,
            inReplyTo: envelope.inReplyTo || undefined,

            headers: extended ? headers : undefined,

            text: textId
                ? {
                      id: textId,
                      encodedSize: encodedTextSize,
                      plain: textContents?.[0]?.toString(),
                      html: textContents?.[1]?.toString(),
                      hasMore: textContents?.[0] || textContents?.[1] ? false : undefined
                  }
                : undefined,

            preview: messageData.snippet
        };

        for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
            if (result.labels && result.labels.includes(specialUseTag)) {
                result.messageSpecialUse = specialUseTag;
                break;
            }
        }

        return result;
    }

    async listMessages(query) {
        console.log('LIST MESSAGES', query);
        await this.prepare();

        const accessToken = await this.getToken();

        let pageSize = Math.abs(Number(query.pageSize) || 20);
        let requestQuery = {
            maxResults: pageSize
        };

        let path;
        if (query.path) {
            path = []
                .concat(query.path || '')
                .join('/')
                .replace(/^INBOX(\/|$)/gi, 'INBOX');

            let labelsResult = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/labels`);
            let label = labelsResult.labels.find(entry => entry.name === path || entry.id === path);
            if (!label) {
                return false;
            }
            requestQuery.labelIds = label.id;
        }

        let messageList = [];
        let listingResult = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/messages`, 'get', requestQuery);

        let promises = [];

        let resolvePromises = async () => {
            if (!promises.length) {
                return;
            }
            let resultList = await Promise.allSettled(promises);
            for (let entry of resultList) {
                if (entry.status === 'rejected') {
                    throw entry.reason;
                }
                if (entry.value) {
                    messageList.push(this.formatMessage(entry.value, { path }));
                }
            }
            promises = [];
        };

        for (let { id: message } of listingResult.messages) {
            promises.push(this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${message}`));
            if (promises.length > LIST_BATCH_SIZE) {
                await resolvePromises();
            }
        }
        await resolvePromises();

        return messageList;
    }

    async getRawMessage(messageId) {
        await this.prepare();

        const accessToken = await this.getToken();

        const requestQuery = {
            format: 'raw'
        };
        const result = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}`, 'get', requestQuery);

        return result?.raw ? Buffer.from(result?.raw, 'base64url') : null;
    }

    async deleteMessage(messageId /*, force*/) {
        await this.prepare();

        const accessToken = await this.getToken();

        // Move to trash
        const url = `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}/trash`;
        const result = await this.oAuth2Client.request(accessToken, url, 'post', Buffer.alloc(0));

        return {
            deleted: result && result.labelIds?.includes('TRASH'),
            moved: {
                message: result.id
            }
        };
    }

    async moveMessage(messageId, target) {
        target = target || {};
        // target.path

        await this.prepare();

        const accessToken = await this.getToken();

        const requestQuery = {
            format: 'minimal'
        };

        let path = (target.path || '').toString().trim();

        let label;

        if (/^inbox$/i.test(path)) {
            label = 'INBOX';
        }

        for (let key of Object.keys(SYSTEM_NAMES)) {
            if (path === SYSTEM_NAMES[key]) {
                label = key;
            }
        }

        if (!label) {
            label = path;
        }

        const messageData = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}`, 'get', requestQuery);

        console.log({ label, p: path.toUpperCase(), s: SYSTEM_NAMES[path.toUpperCase()] });

        if (!messageData) {
            return false;
        }

        if (messageData.labelIds.includes(label)) {
            return true;
        }

        console.log(messageData);
    }

    async getAttachmentContent(attachmentId) {
        let sepPos = attachmentId.indexOf('.');
        if (sepPos < 0) {
            return null;
        }
        const [messageId, contentType, disposition, filename] = msgpack.decode(Buffer.from(attachmentId.substring(0, sepPos), 'base64url'));
        const id = attachmentId.substring(sepPos + 1);

        await this.prepare();

        const accessToken = await this.getToken();

        const requestQuery = {};
        const result = await this.oAuth2Client.request(
            accessToken,
            `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}/attachments/${id}`,
            'get',
            requestQuery
        );

        return {
            content: result?.data ? Buffer.from(result?.data, 'base64url') : null,
            contentType,
            disposition,
            filename
        };
    }

    async getAttachment(attachmentId) {
        let attachmentData = await this.getAttachmentContent(attachmentId);

        if (!attachmentData || !attachmentData.content) {
            return false;
        }

        let filenameParam = '';
        if (attachmentData.filename) {
            let isCleartextFilename = attachmentData.filename && /^[a-z0-9 _\-()^[\]~=,+*$]$/i.test(attachmentData.filename);
            if (isCleartextFilename) {
                filenameParam = `; filename=${JSON.stringify(attachmentData.filename)}`;
            } else {
                filenameParam = `; filename=${JSON.stringify(he.encode(attachmentData.filename))}; filename*=utf-8''${encodeURIComponent(
                    attachmentData.filename
                )}`;
            }
        }

        const content = {
            headers: {
                'content-type': attachmentData.mimeType || 'application/octet-stream',
                'content-disposition': 'attachment' + filenameParam
            },
            contentType: attachmentData.contentType,
            filename: attachmentData.filename,
            disposition: attachmentData.disposition,
            data: attachmentData.content
        };

        return content;
    }

    async getMessage(messageId, options) {
        options = options || {};
        await this.prepare();

        const accessToken = await this.getToken();

        const requestQuery = {
            format: 'full'
        };
        const messageData = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}`, 'get', requestQuery);

        let result = this.formatMessage(messageData, { extended: true, textType: options.textType });

        console.log('---MESSAGE----');
        console.log(JSON.stringify(messageData));

        console.log(result);

        return result;
    }

    async getText(textId, options) {
        options = options || {};
        await this.prepare();

        const accessToken = await this.getToken();

        const [messageId, textParts] = msgpack.decode(Buffer.from(textId, 'base64url'));

        const bodyParts = new Map();

        textParts[0].forEach(p => {
            bodyParts.set(p, 'text');
        });

        textParts[1].forEach(p => {
            bodyParts.set(p, 'html');
        });

        const requestQuery = {
            format: 'full'
        };
        const messageData = await this.oAuth2Client.request(accessToken, `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}`, 'get', requestQuery);

        const response = {};

        if (options.textType && options.textType !== '*') {
            response[options.textType] = '';
        }

        const textContent = {};
        const walkBodyParts = node => {
            let textType = bodyParts.has(node.partId) ? bodyParts.get(node.partId) : false;

            if (textType && (options.textType === '*' || options.textType === textType) && node.body?.data) {
                if (!textContent[textType]) {
                    textContent[textType] = [];
                }
                textContent[textType].push(Buffer.from(node.body.data, 'base64'));
            }

            if (Array.isArray(node.parts)) {
                for (let part of node.parts) {
                    walkBodyParts(part);
                }
            }
        };
        walkBodyParts(messageData.payload);

        for (let key of Object.keys(textContent)) {
            response[key] = textContent[key].map(buf => buf.toString()).join('\n');
        }

        response.hasMore = false;

        return response;
    }

    // stub. no support or need for subconnections
    async subconnections() {
        return [];
    }
}

module.exports = { GmailClient };

if (/gmail-client\.js$/.test(process.argv[1])) {
    console.log('RUN AS STANDALONE');

    let main = async () => {
        const { redis } = require('../db'); // eslint-disable-line global-require

        let gmailClient = new GmailClient('andris', { redis });

        let mailboxes = await gmailClient.listMailboxes();
        console.log(mailboxes);

        let messages = await gmailClient.listMessages({ path: 'INBOX' });
        console.log(JSON.stringify(messages, false, 2));

        let deleted = false;

        for (let msg of messages) {
            if (/testkiri/i.test(msg.subject) && !deleted) {
                deleted = true;

                console.log('DELETING', msg.id);
                let y = await gmailClient.deleteMessage(msg.id, true);
                console.log('DELETE RESULT', y);
            }

            if (msg.attachments && msg.attachments.length) {
                await gmailClient.getMessage(msg.id, { textType: '*' });

                const textContent = await gmailClient.getText(msg.text.id, { textType: '*' });
                console.log('TEXT CONTENT', textContent);

                console.log('MOVE MESSAGE');
                let moveRes = await gmailClient.moveMessage(msg.id, { path: 'Inbox' });
                console.log('MOVE RES', moveRes);

                let raw = await gmailClient.getRawMessage(msg.id);
                await fs.promises.writeFile(`/Users/andris/Desktop/${msg.id}.eml`, raw);
                for (let a of msg.attachments) {
                    let attachment = await gmailClient.getAttachment(a.id);
                    console.log(attachment);
                    let s = fs.createWriteStream(`/Users/andris/Desktop/${a.filename}`);

                    console.log('PIPING TO STREAM');
                    await new Promise((r, e) => {
                        s.once('finish', r);
                        s.once('error', e);

                        s.write(attachment.data);
                        s.end();
                    });
                    console.log('DONE');

                    //await fs.promises.writeFile(`/Users/andris/Desktop/${a.filename}`, attachment);
                    process.exit();
                }
            }
        }
    };

    main()
        .catch(err => console.error(require('util').inspect(err, false, 22))) // eslint-disable-line global-require
        .finally(() => process.exit());
}
