'use strict';

const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const msgpack = require('msgpack5')();
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');
const he = require('he');
const { BaseClient } = require('./base-client');

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
  ✅ paging - not implemented
  -  search - partially implemented, missing emailId, threadId
✅ getText
✅ getMessage
❌ updateMessage
❌ updateMessages
✅ listMailboxes
❌ moveMessage
❌ moveMessages
✅ deleteMessage - no force option
❌ deleteMessages
✅ getRawMessage
🟡 getQuota - not supported
❌ createMailbox
❌ renameMailbox
❌ deleteMailbox
✅ getAttachment
❌ submitMessage
❌ queueMessage
❌ uploadMessage
🟡 subconnections - not supported

*/

class PageCursor {
    static create(cursorStr) {
        return new PageCursor(cursorStr);
    }

    constructor(cursorStr) {
        this.type = 'gmail';
        this.cursorList = [];
        this.cursorStr = '';
        if (cursorStr) {
            let splitPos = cursorStr.indexOf('_');
            if (splitPos >= 0) {
                let cursorType = cursorStr.substring(0, splitPos);
                cursorStr = cursorStr.substring(splitPos + 1);
                if (cursorType && this.type !== cursorType) {
                    let error = new Error('Invalid cursor');
                    error.code = 'InvalidCursorType';
                    throw error;
                }
            }

            try {
                this.cursorList = msgpack.decode(Buffer.from(cursorStr, 'base64url'));
                this.cursorStr = cursorStr;
            } catch (err) {
                this.cursorList = [];
                this.cursorStr = '';
            }
        }
    }

    toString() {
        return this.cursorStr;
    }

    currentPage() {
        if (this.cursorList.length < 1) {
            return { page: 0, cursor: '', pageCursor: '' };
        }

        return { page: this.cursorList.length, cursor: this.decodeCursorValue(this.cursorList.at(-1)), pageCursor: this.cursorStr };
    }

    nextPageCursor(nextPageCursor) {
        if (!nextPageCursor) {
            return null;
        }
        let encodedCursor = this.encodeCursorValue(nextPageCursor);
        // if nextPageCursor is an array, then it will be flattened, have to push instead
        let cursorListCopy = this.cursorList.concat([]);
        cursorListCopy.push(encodedCursor);
        return this.type + '_' + msgpack.encode(cursorListCopy).toString('base64url');
    }

    prevPageCursor() {
        if (this.cursorList.length <= 1) {
            return null;
        }

        return this.type + '_' + msgpack.encode(this.cursorList.slice(0, this.cursorList.length - 1)).toString('base64url');
    }

    encodeCursorValue(cursor) {
        let hexNr = BigInt(cursor).toString(16);

        // split to chunks of 16. This monstrosity ensures that we start from the right
        let chunks = hexNr
            .split('')
            .reverse()
            .join('')
            .split(/(.{16})/)
            .filter(v => v)
            .reverse()
            .map(v => v.split('').reverse().join(''))
            .map(v => {
                let n = BigInt(`0x${v}`);
                let buf = Buffer.alloc(8);
                buf.writeBigUInt64LE(n, 0);
                return buf;
            });

        return chunks.length > 1 ? chunks : chunks[0];
    }

    decodeCursorValue(value) {
        if (!value || !value.length) {
            return null;
        }

        if (typeof value[0] === 'number') {
            value = [value];
        }

        let hexNr = value
            .map(buf => {
                let n = buf.readBigUInt64LE(0);
                let hexN = n.toString(16);
                if (hexN.length < 16) {
                    // add missing zero padding
                    hexN = '0'.repeat(16 - hexN.length) + hexN;
                }
                return hexN;
            })
            .join('');

        return BigInt('0x' + hexNr).toString(10);
    }
}

class GmailClient extends BaseClient {
    constructor(account, options) {
        super(account, options);
    }

    async request(...args) {
        let result, accessToken;
        try {
            accessToken = await this.getToken();
        } catch (err) {
            console.log(err);
            throw err;
        }

        try {
            result = await await this.oAuth2Client.request(accessToken, ...args);
        } catch (err) {
            console.log(err);
            throw err;
        }

        return result;
    }

    // PUBLIC METHODS

    async listMailboxes(options) {
        console.log('LIST MAILBOXES', options);
        await this.prepare();
        console.log(1);
        const accessToken = await this.getToken();
        console.log(2, accessToken);
        let labelsResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/labels`);
        console.log(3, labelsResult);
        let labels = labelsResult.labels.filter(label => !SKIP_LABELS.includes(label.id));

        let resultLabels;
        if (options && options.counters) {
            resultLabels = [];
            for (let label of labels) {
                let labelResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/labels/${label.id}`);
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

        return mailboxes;
    }

    async listMessages(query) {
        console.log('LIST MESSAGES', query);
        await this.prepare();

        const accessToken = await this.getToken();

        let pageSize = Math.abs(Number(query.pageSize) || 20);
        let requestQuery = {
            maxResults: pageSize
        };

        let pageCursor = PageCursor.create(query.cursor);

        let path;
        if (query.path) {
            path = []
                .concat(query.path || '')
                .join('/')
                .replace(/^INBOX(\/|$)/gi, 'INBOX');

            let labelsResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/labels`);
            let label = labelsResult.labels.find(entry => entry.name === path || entry.id === path);
            if (!label) {
                return false;
            }
            requestQuery.labelIds = [label.id];
        }

        let messageList = [];

        if (query.search) {
            if (query.search.emailId) {
                // Return only a single matching email

                let messageEntry = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${query.search.emailId}`, 'get', {
                    format: 'full'
                });
                if (messageEntry) {
                    messageList.push(this.formatMessage(messageEntry, { path }));
                }

                let messageCount = messageList.length;
                let pages = Math.ceil(messageCount / pageSize);

                return {
                    total: messageCount,
                    page: 0,
                    pages,
                    nextPageCursor: null,
                    prevPageCursor: null,
                    messages: messageList
                };
            }

            if (query.search.threadId) {
                // Threading is a special case
                let threadListingResult = await this.oAuth2Client.request(
                    accessToken,
                    `${GMAIL_API_BASE}/gmail/v1/users/me/threads/${query.search.threadId}`,
                    'get',
                    {
                        format: 'full'
                    }
                );

                let messageCount = threadListingResult?.messages?.length || 0;
                let currentPage = pageCursor.currentPage();

                console.log('CURRENT PAGE', query.cursor, currentPage);

                let nextPageToken = null;
                if (messageCount > pageSize) {
                    let pageStart = 0;

                    if (currentPage?.cursor) {
                        pageStart = Number(currentPage.cursor) || 0;
                    }

                    if (pageStart + pageSize < messageCount) {
                        nextPageToken = (pageStart + pageSize).toString(10);
                    }

                    // extract messages for the current page only
                    threadListingResult.messages = threadListingResult.messages.slice(pageStart, pageStart + pageSize, messageCount);
                }

                if (threadListingResult?.messages) {
                    for (let entry of threadListingResult.messages) {
                        messageList.push(this.formatMessage(entry, { path }));
                    }
                }

                let pages = Math.ceil(messageCount / pageSize);
                let nextPageCursor = pageCursor.nextPageCursor(nextPageToken);
                let prevPageCursor = pageCursor.prevPageCursor();

                console.log('THREAD LISTING');
                console.log(JSON.stringify(messageList, false, 2));

                return {
                    total: messageCount,
                    page: currentPage.page,
                    pages,
                    nextPageCursor,
                    prevPageCursor,
                    messages: messageList
                };
            }

            // NB! Might throw if using unsupported search terms
            const preparedQuery = this.prepareQuery(query.search);
            if (preparedQuery) {
                requestQuery.q = this.prepareQuery(query.search);
            }
        }

        let currentPage = pageCursor.currentPage();
        if (currentPage?.cursor) {
            requestQuery.pageToken = currentPage.cursor;
        }

        console.log('REQUEST QUERY', requestQuery);

        let listingResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages`, 'get', requestQuery);
        let messageCount = listingResult.resultSizeEstimate;

        let pages = Math.ceil(messageCount / pageSize);

        let nextPageCursor = pageCursor.nextPageCursor(listingResult.nextPageToken);
        let prevPageCursor = pageCursor.prevPageCursor();

        console.log('LISTING RESULT', listingResult);
        console.log('NEXT PAGE CURSOR', nextPageCursor);
        console.log('PREV PAGE CURSOR', prevPageCursor);

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

        return {
            total: messageCount,
            page: currentPage.page,
            pages,
            nextPageCursor,
            prevPageCursor,
            messages: messageList
        };
    }

    async getRawMessage(messageId) {
        await this.prepare();

        const requestQuery = {
            format: 'raw'
        };
        const result = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}`, 'get', requestQuery);

        return result?.raw ? Buffer.from(result?.raw, 'base64url') : null;
    }

    async deleteMessage(messageId /*, force*/) {
        await this.prepare();

        // Move to trash
        const url = `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}/trash`;
        const result = await this.request(url, 'post', Buffer.alloc(0));

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

        const messageData = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}`, 'get', requestQuery);

        console.log({ label, p: path.toUpperCase(), s: SYSTEM_NAMES[path.toUpperCase()] });

        if (!messageData) {
            return false;
        }

        if (messageData.labelIds.includes(label)) {
            return true;
        }

        console.log(messageData);
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

        const requestQuery = {
            format: 'full'
        };
        const messageData = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}`, 'get', requestQuery);

        let result = this.formatMessage(messageData, { extended: true, textType: options.textType });

        console.log('---MESSAGE----');
        console.log(JSON.stringify(messageData));

        console.log(result);

        return result;
    }

    async getText(textId, options) {
        options = options || {};
        await this.prepare();

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
        const messageData = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${messageId}`, 'get', requestQuery);

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

    // PRIVATE METHODS

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

    formatSearchTerm(term) {
        term = (term || '')
            .toString()
            .replace(/[\s"]+/g, ' ')
            .trim();
        if (term.indexOf(' ') >= 0) {
            return `"${term}"`;
        }
        return term;
    }

    // convert IMAP SEARCH query object to a Gmail API search query
    prepareQuery(search) {
        search = search || {};

        const queryParts = [];

        // not supported search terms
        for (let disabledKey of ['seq', 'uid', 'paths', 'answered', 'deleted', 'draft']) {
            if (disabledKey in search) {
                let error = new Error(`Unsupported search term "${disabledKey}"`);
                error.code = 'UnsupportedSearchTerm';
                throw error;
            }
        }

        // flagged
        if (typeof search.flagged === 'boolean') {
            queryParts.push(`${!search.flagged ? '-' : ''}is:starred`);
        }

        // unseen
        if (typeof search.unseen === 'boolean') {
            queryParts.push(`is:${search.unseen ? 'unread' : 'read'}`);
        }

        // seen
        if (typeof search.seen === 'boolean') {
            queryParts.push(`is:${search.unseen ? 'read' : 'unread'}`);
        }

        for (let key of ['from', 'to', 'cc', 'bcc', 'subject']) {
            if (search[key]) {
                queryParts.push(`${key}:${this.formatSearchTerm(search[key])}`);
            }
        }

        for (let headerKey of Object.keys(search.header || {})) {
            switch (headerKey.toLowerCase().trim()) {
                case 'message-id':
                    queryParts.push(`rfc822msgid:${this.formatSearchTerm(search.header[headerKey])}`);
                    break;
                default: {
                    let error = new Error(`Unsupported search header "${headerKey}"`);
                    error.code = 'UnsupportedSearchTerm';
                    throw error;
                }
            }
        }

        // whatever is used in the raw search, just prepend
        if (search.gmailRaw && typeof search.gmailRaw === 'string') {
            queryParts.push(search.gmailRaw);
        }

        // body search
        if (search.body && typeof search.body === 'string') {
            queryParts.push(`${this.formatSearchTerm(search.body)}`);
        }

        return queryParts.join(' ').trim();
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

        let messages;
        let cursor; //= 'gmail_kcQIAwAAAAAAAAA';

        while (Date.now()) {
            messages = await gmailClient.listMessages({
                path: 'INBOX',
                pageSize: 3,
                search: {
                    emailId: '18f765767efa70c0',
                    threadId: '18f4281215decd54' /*from: 'notify@chartmogul.com'*/
                },
                cursor
            });

            console.log(messages);
            if (!messages.nextPageCursor) {
                break;
            }
            cursor = messages.nextPageCursor;
        }

        let deleted = false;

        for (let msg of messages.messages) {
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
