'use strict';

const { BaseClient } = require('./base-client');
const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const msgpack = require('msgpack5')();
const he = require('he');
const { emitChangeEvent } = require('../tools');
const { mimeHtml } = require('@postalsys/email-text-tools');

const { REDIS_PREFIX, AUTH_ERROR_NOTIFY, AUTH_SUCCESS_NOTIFY, EMAIL_SENT_NOTIFY } = require('../consts');

const OUTLOOK_API_BASE = 'https://graph.microsoft.com/v1.0';

/*
✅ listMessages
  ✅ paging - cursor + page nr
  ✅ search queries - no support for to/cc/bcc queries
✅ getText
✅ getMessage
✅ updateMessage
🟡 updateMessages - not supported, throws
✅ listMailboxes
✅ moveMessage
🟡 moveMessages - not supported, throws
✅ deleteMessage 
🟡 deleteMessages - not supported, throws
✅ getRawMessage
🟡 getQuota - not supported
✅ createMailbox
✅ renameMailbox
✅ deleteMailbox
✅ getAttachment
✅ submitMessage
✅ uploadMessage - only drafts. Can not change draft status
🟡 subconnections - not supported
*/

class OutlookClient extends BaseClient {
    constructor(account, options) {
        super(account, options);

        this.cachedAccessToken = null;
        this.cachedAccessTokenRaw = null;

        // pseudo path for webhooks
        this.path = '\\All';
        this.listingEntry = { specialUse: '\\All' };
    }

    async request(...args) {
        let result, accessToken;
        try {
            accessToken = await this.getToken();
        } catch (err) {
            this.logger.error({ msg: 'Failed to load access token', account: this.account, err });
            throw err;
        }

        try {
            if (!this.oAuth2Client) {
                await this.getClient();
            }

            let [url, method, payload, options = {}] = args;

            options.headers = options.headers || {};

            // https://learn.microsoft.com/en-us/graph/outlook-immutable-id
            options.headers.Prefer = 'IdType="ImmutableId"';

            result = await this.oAuth2Client.request(accessToken, url, method, payload, options);
        } catch (err) {
            this.logger.error({ msg: 'Failed to run API request', account: this.account, err });
            throw err;
        }

        return result;
    }

    // PUBLIC METHODS

    async init() {
        await this.getAccount();
        await this.getClient(true);

        let accountData = await this.accountObject.loadAccountData(this.account, false);

        let profileRes;
        try {
            profileRes = await this.request(`${OUTLOOK_API_BASE}/me`);
        } catch (err) {
            this.state = 'authenticationError';
            await this.setStateVal();

            err.authenticationFailed = true;

            await this.notify(false, AUTH_ERROR_NOTIFY, {
                response: err.oauthRequest?.response?.error?.message || err.response,
                serverResponseCode: 'ApiRequestError'
            });

            throw err;
        }

        let updates = {};

        if (profileRes.userPrincipalName && accountData.oauth2.auth?.user !== profileRes.userPrincipalName) {
            updates.oauth2 = {
                partial: true,
                auth: Object.assign(accountData.oauth2.auth || {}, {
                    // update username
                    user: profileRes.userPrincipalName
                })
            };
        }

        if (Object.keys(updates).length) {
            await this.accountObject.update(updates);
        }

        this.state = 'connected';
        await this.setStateVal();

        let prevConnectedCount = await this.redis.hget(this.getAccountKey(), `state:count:connected`);
        let isFirstSuccessfulConnection = prevConnectedCount === '0'; // string zero means the account has been initialized but not yet connected

        let isiInitial = !!isFirstSuccessfulConnection;

        if (!isFirstSuccessfulConnection) {
            // check if the connection was previously in an errored state
            let prevLastErrorState = await this.redis.hget(this.getAccountKey(), 'lastErrorState');
            if (prevLastErrorState) {
                try {
                    prevLastErrorState = JSON.parse(prevLastErrorState);
                } catch (err) {
                    // ignore
                }
            }

            if (prevLastErrorState && typeof prevLastErrorState === 'object' && Object.keys(prevLastErrorState).length) {
                // was previously errored
                isFirstSuccessfulConnection = true;
            }
        }

        if (isFirstSuccessfulConnection) {
            this.logger.info({ msg: 'Successful login without a previous active session', account: this.account, isiInitial, prevActive: false });
            await this.notify(false, AUTH_SUCCESS_NOTIFY, {
                user: accountData.oauth2?.auth?.user
            });
        } else {
            this.logger.info({ msg: 'Successful login with a previous active session', account: this.account, isiInitial, prevActive: true });
        }

        await this.redis.hSetExists(this.getAccountKey(), 'lastErrorState', '{}');
        await emitChangeEvent(this.logger, this.account, 'state', this.state);

        // additional operations

        try {
            await this.listMailboxes();
        } catch (err) {
            this.logger.error({ msg: 'Failed to renew mailbox folder cache', err });
        }
    }

    async close() {
        this.closed = true;
        return null;
    }

    async delete() {
        this.closed = true;
        return null;
    }

    async reconnect() {
        return await this.init();
    }

    // TODO: check for changes (added, deleted folders)
    async listMailboxes(options) {
        await this.prepare();

        let mailboxListing;

        let cachedListing = await this.getCachedMailboxListing();
        if (!cachedListing || options?.statusQuery?.messages || (await this.renewMailboxFolderCache())) {
            // Has changes or counters requested
            mailboxListing = await this.getMailboxListing();
            try {
                await this.redis.hset(this.getAccountCacheKey(), 'outlookMailboxListing', JSON.stringify(mailboxListing));
            } catch (err) {
                this.logger.error({ msg: 'Failed to cache mailbox listing', err });
            }

            if (!cachedListing && !options?.statusQuery?.messages) {
                // Force delta update as it was not called previously
                await this.renewMailboxFolderCache();
            }
        } else {
            // No changes, use cached listing
            mailboxListing = cachedListing;
        }

        let mailboxes = mailboxListing
            .map(entry => {
                let folderData = {
                    id: entry.id,
                    path: entry.pathName,
                    delimiter: '/',
                    parentPath: entry.parentPath,
                    name: entry.displayName,
                    listed: true,
                    subscribed: true
                };

                if (entry.specialUse) {
                    folderData.specialUse = entry.specialUse;
                    folderData.specialUseSource = 'extension';
                }

                if (options?.statusQuery?.messages) {
                    folderData.status = {
                        messages: entry.totalItemCount,
                        unseen: entry.unreadItemCount
                    };
                }

                return folderData;
            })
            .sort((a, b) => {
                if (a.path === 'INBOX' || a.specialUse === '\\Inbox') {
                    return -1;
                } else if (b.path === 'INBOX' || b.specialUse === '\\Inbox') {
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

    async listMessages(query /*, options*/) {
        await this.prepare();

        let path = [].concat(query.path || []).join('/');

        let folder;
        let cachedListing;
        let mailboxListing;

        if (path === '\\All') {
            folder = null;
            cachedListing = await this.getCachedMailboxListing();
            mailboxListing = cachedListing || (await this.getMailboxListing());
        } else {
            folder = await this.resolveFolder(path);
            if (!folder) {
                let error = new Error('Listing failed');
                error.info = {
                    response: 'Not able to find mailbox folder'
                };
                error.code = 'NotFound';
                error.statusCode = 404;
                throw error;
            }
            path = folder.pathName;
        }

        let quickResolveFolder = parentFolderId => {
            if (folder) {
                return folder;
            }
            return mailboxListing.find(entry => entry.id === parentFolderId);
        };

        let page = Number(query.page) || 0;
        let pageSize = Math.abs(Number(query.pageSize) || 20);

        if (query.cursor) {
            let cursorPage = this.decodeCursorStr(query.cursor);
            if (typeof cursorPage === 'number' && cursorPage >= 0) {
                page = cursorPage;
            }
        }

        let requestQuery = {
            $count: 'true',
            $top: pageSize,
            $skip: page * pageSize,
            $orderBy: 'receivedDateTime desc',
            $select: [
                'id',
                'conversationId',
                'receivedDateTime',
                'isRead',
                'isDraft',
                'flag',
                'body',
                'subject',
                'from',
                'replyTo',
                'sender',
                'toRecipients',
                'ccRecipients',
                'bccRecipients',
                'internetMessageId',
                'bodyPreview'
            ]
                .concat(!folder ? 'parentFolderId' : [])
                .join(','),
            $expand: 'attachments($select=id,name,contentType,size,isInline,microsoft.graph.fileAttachment/contentId)'
        };

        if (query.search) {
            const { $search, $filter } = this.prepareQuery(query.search);
            if ($search) {
                requestQuery.$search = `"${$search}"`;
            }

            if ($filter) {
                requestQuery.$filter = $filter;
            }

            // no paging for search results
            delete requestQuery.$skip;
            requestQuery.$top = 100;
        }

        let messages = [];
        let totalMessages;

        // list messages
        try {
            let listing = await this.request(`${OUTLOOK_API_BASE}/me/${folder ? `mailFolders/${folder.id}/` : ''}messages`, 'get', requestQuery);
            totalMessages = !isNaN(listing['@odata.count']) ? Number(listing['@odata.count']) : 0;

            messages =
                listing?.value?.map(messageData =>
                    this.formatMessage(messageData, { path: quickResolveFolder(messageData.parentFolderId)?.pathName, showPath: !folder })
                ) || [];
        } catch (err) {
            this.logger.error({
                msg: 'Failed to list messages',
                mailboxId: folder?.id,
                path,
                err
            });
            throw err;
        }

        let pages = Math.ceil(totalMessages / pageSize) || 1;

        if (page < 0) {
            page = 0;
        }

        let nextPageCursor = page < pages - 1 ? this.encodeCursorString(page + 1) : null;
        let prevPageCursor = page > 0 ? this.encodeCursorString(Math.min(page - 1, pages - 1)) : null;

        return {
            total: totalMessages,
            page,
            pages,
            nextPageCursor,
            prevPageCursor,
            messages
        };
    }

    async getRawMessage(messageId) {
        await this.prepare();

        let raw;

        try {
            raw = await this.request(`${OUTLOOK_API_BASE}/me/messages/${messageId}/$value`, 'get', Buffer.alloc(0), { returnText: true });
        } catch (err) {
            switch (err.oauthRequest?.status) {
                case 404: {
                    let error = new Error('Unknown message');
                    error.info = {
                        response: `Message does not exist`
                    };
                    error.code = 'NotFound';
                    error.statusCode = 404;
                    throw error;
                }

                case 400: {
                    let error = new Error('Invalid request');
                    error.info = {
                        response: err.oauthRequest?.response?.error?.message || `Invalid request`
                    };
                    error.code = err.oauthRequest?.response?.error?.code || 'InvalidRequest';
                    error.statusCode = 400;
                    throw error;
                }

                default:
                    this.logger.error({
                        msg: 'Failed to fetch raw message',
                        messageId,
                        err
                    });
                    throw err;
            }
        }

        return raw ? Buffer.from(raw) : null;
    }

    async deleteMessage(messageId, force) {
        await this.prepare();

        if (force) {
            try {
                await this.request(`${OUTLOOK_API_BASE}/me/messages/${messageId}`, 'delete', Buffer.alloc(0), { returnText: true });
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to delete message',
                    messageId,
                    err
                });

                switch (err?.oauthRequest?.response?.error?.code) {
                    case 'ErrorCannotDeleteObject':
                        // does not exist
                        return {
                            deleted: false
                        };

                    default:
                        throw err;
                }
            }

            return {
                deleted: true
            };
        }

        // Move to trash
        let messageData;
        try {
            messageData = await this.request(`${OUTLOOK_API_BASE}/me/messages/${messageId}/move`, 'post', {
                destinationId: 'deleteditems'
            });
            if (!messageData) {
                throw new Error('Failed to move message to Trash');
            }
        } catch (err) {
            this.logger.error({
                msg: 'Failed to move message to Trash',
                messageId,
                err
            });
            throw err;
        }

        let folder;
        try {
            folder = await this.resolveFolder(messageData.parentFolderId, { byId: true });
        } catch (err) {
            this.logger.error({
                msg: 'Failed to resolve folder for message',
                messageId,
                err
            });
        }

        return {
            deleted: true,
            moved: {
                destination: folder?.pathName,
                message: messageId
            }
        };
    }
    async deleteMessages(/*path, search*/) {
        let error = new Error('Method not available');
        error.info = {
            response: `Method is not available for MS Graph API accounts`
        };
        error.code = 'NotAvailable';
        error.statusCode = 404;
        throw error;
    }

    // MS Graph API allows to manage only \Seen and \Flagged
    async updateMessage(messageId, updates) {
        await this.prepare();
        updates = updates || {};

        let addFlags = updates.flags?.add || [];
        let deleteFlags = updates.flags?.delete || [];

        if (updates.flags?.set) {
            for (let flag of ['\\Seen', '\\Flagged']) {
                if (updates.flags.set.includes(flag)) {
                    addFlags.push(flag);
                } else {
                    deleteFlags.push(flag);
                }
            }
        }

        let flagUpdates = {};

        if (addFlags.includes('\\Seen')) {
            flagUpdates.isRead = true;
        }
        if (deleteFlags.includes('\\Seen')) {
            flagUpdates.isRead = false;
        }

        if (addFlags.includes('\\Flagged')) {
            flagUpdates.flag = { flagStatus: 'flagged' };
        }
        if (deleteFlags.includes('\\Flagged')) {
            flagUpdates.flag = { flagStatus: 'notFlagged' };
        }

        let modifyResult;

        try {
            modifyResult = await this.request(`${OUTLOOK_API_BASE}/me/messages/${messageId}`, 'patch', flagUpdates);
        } catch (err) {
            this.logger.error({
                msg: 'Failed to update message',
                messageId,
                flagUpdates,
                err
            });

            switch (err.oauthRequest?.status) {
                case 400: {
                    let error = new Error('Invalid request');
                    error.info = {
                        response: err.oauthRequest?.response?.error?.message || `Invalid request`
                    };
                    error.code = err.oauthRequest?.response?.error?.code || 'InvalidRequest';
                    error.statusCode = 400;
                    throw error;
                }

                default:
                    throw err;
            }
        }

        const result = [];
        if (modifyResult.isRead) {
            result.push('\\Seen');
        }
        if (modifyResult.isDraft) {
            result.push('\\Draft');
        }
        if (modifyResult.flag?.flagStatus === 'flagged') {
            result.push('\\Flagged');
        }

        let response = {
            flags: Object.assign({}, updates.flags || {}, { result })
        };

        return response;
    }

    async updateMessages(/*path, search, updates*/) {
        let error = new Error('Method not available');
        error.info = {
            response: `Method is not available for MS Graph API accounts`
        };
        error.code = 'NotAvailable';
        error.statusCode = 404;
        throw error;
    }

    async moveMessage(messageId, target) {
        await this.prepare();

        let path = [].concat(target?.path || []).join('/');

        let targetFolder = await this.resolveFolder(path);
        if (!targetFolder) {
            let error = new Error('Move failed');
            error.info = {
                response: 'Not able to find target folder'
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }

        let messageData;
        try {
            messageData = await this.request(`${OUTLOOK_API_BASE}/me/messages/${messageId}/move`, 'post', {
                destinationId: targetFolder.id
            });
            if (!messageData) {
                throw new Error('Failed to move message');
            }
        } catch (err) {
            this.logger.error({
                msg: 'Failed to move message',
                messageId,
                target: targetFolder.pathName,
                err
            });

            switch (err?.oauthRequest?.response?.error?.code) {
                case 'ErrorItemNotFound': {
                    let error = new Error('Move failed');
                    error.info = {
                        response: 'Not able to find source message'
                    };
                    error.code = 'NotFound';
                    error.statusCode = 404;
                    throw error;
                }

                default: {
                    let error = new Error('Move failed');
                    error.info = {
                        response: err?.oauthRequest?.response?.error?.message
                    };
                    error.code = err?.oauthRequest?.response?.error?.code;
                    error.statusCode = 400;
                    throw error;
                }
            }
        }

        return {
            path: targetFolder.pathName,
            id: messageData.id
        };
    }

    async moveMessages(/*source, search, target*/) {
        let error = new Error('Method not available');
        error.info = {
            response: `Method is not available for MS Graph API accounts`
        };
        error.code = 'NotAvailable';
        error.statusCode = 404;
        throw error;
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
            data: attachmentData.content
        };

        return content;
    }

    async getMessage(messageId, options) {
        options = options || {};

        if (options.webSafeHtml) {
            options.textType = '*';
            options.embedAttachedImages = true;
            options.preProcessHtml = true;
        }

        await this.prepare();

        let messageData, path, specialUse;

        try {
            messageData = await this.request(`${OUTLOOK_API_BASE}/me/messages/${messageId}`, 'get', {
                // 'internetMessageHeaders' is not included by default, so have to list all required fields
                $select: [
                    'id',
                    'conversationId',
                    'receivedDateTime',
                    'isRead',
                    'isDraft',
                    'flag',
                    'body',
                    'subject',
                    'from',
                    'replyTo',
                    'sender',
                    'toRecipients',
                    'ccRecipients',
                    'bccRecipients',
                    'internetMessageId',
                    'bodyPreview',
                    'internetMessageHeaders'
                ].join(','),
                $expand: 'attachments($select=id,name,contentType,size,isInline,microsoft.graph.fileAttachment/contentId)'
            });
        } catch (err) {
            switch (err.oauthRequest?.status) {
                case 404: {
                    let error = new Error('Unknown message');
                    error.info = {
                        response: `Message does not exist`
                    };
                    error.code = 'NotFound';
                    error.statusCode = 404;
                    throw error;
                }

                case 400: {
                    let error = new Error('Invalid request');
                    error.info = {
                        response: err.oauthRequest?.response?.error?.message || `Invalid request`
                    };
                    error.code = err.oauthRequest?.response?.error?.code || 'InvalidRequest';
                    error.statusCode = 400;
                    throw error;
                }

                default:
                    this.logger.error({
                        msg: 'Failed to fetch message data',
                        messageId,
                        err
                    });
                    throw err;
            }
        }

        if (messageData.parentFolderId) {
            let folder = await this.resolveFolder(messageData.parentFolderId, { byId: true });
            if (!folder) {
                let error = new Error('Listing failed');
                error.info = {
                    response: 'Not able to find mailbox folder'
                };
                error.code = 'NotFound';
                error.statusCode = 404;
                throw error;
            }

            path = folder.pathName;
            specialUse = folder.specialUse;
        }

        const formattedMessage = this.formatMessage(messageData, {
            extended: true,
            path,
            textType: options.textType
        });

        if (options.embedAttachedImages && formattedMessage.text?.html && formattedMessage.attachments) {
            let attachmentMap = new Map();

            for (let attachment of formattedMessage.attachments) {
                let contentId = attachment.contentId && attachment.contentId.replace(/^<|>$/g, '');
                if (contentId && formattedMessage.text.html.indexOf(contentId) >= 0) {
                    attachmentMap.set(contentId, { attachment, content: null });
                }
            }

            for (let entry of attachmentMap.values()) {
                if (!entry.content) {
                    entry.content = await this.getAttachmentContent(entry.attachment.id);
                }
            }

            formattedMessage.text.html = formattedMessage.text.html.replace(/\bcid:([^"'\s>]+)/g, (fullMatch, cidMatch) => {
                if (attachmentMap.has(cidMatch)) {
                    let { content } = attachmentMap.get(cidMatch);
                    if (content.content) {
                        return `data:${content.contentType || 'application/octet-stream'};base64,${content.content.toString('base64')}`;
                    }
                }
                return fullMatch;
            });
        }

        if (options.preProcessHtml && formattedMessage.text && (formattedMessage.text.html || formattedMessage.text.plain)) {
            formattedMessage.text.html = mimeHtml({
                html: formattedMessage.text.html,
                text: formattedMessage.text.plain
            });
            formattedMessage.text.webSafe = true;
        }

        if (specialUse) {
            formattedMessage.messageSpecialUse = specialUse;
        }

        return formattedMessage;
    }

    async getText(textId, options) {
        options = options || {};

        await this.prepare();

        let messageData;

        try {
            messageData = await this.request(`${OUTLOOK_API_BASE}/me/messages/${textId}`, 'get', {
                $select: 'body'
            });
        } catch (err) {
            switch (err.oauthRequest?.status) {
                case 404: {
                    let error = new Error('Unknown message');
                    error.info = {
                        response: `Message does not exist`
                    };
                    error.code = 'NotFound';
                    error.statusCode = 404;
                    throw error;
                }

                case 400: {
                    let error = new Error('Invalid request');
                    error.info = {
                        response: err.oauthRequest?.response?.error?.message || `Invalid request`
                    };
                    error.code = err.oauthRequest?.response?.error?.code || 'InvalidRequest';
                    error.statusCode = 400;
                    throw error;
                }

                default:
                    this.logger.error({
                        msg: 'Failed to fetch message data',
                        messageId: textId,
                        err
                    });
                    throw err;
            }
        }

        let response = {};

        if (options.textType && options.textType !== '*') {
            response[options.textType] = '';
        }

        if (messageData?.body?.contentType) {
            let textContent = messageData.body.content || '';
            if ([messageData?.body?.contentType, '*'].includes(options.textType)) {
                response[messageData.body.contentType] = textContent;
            }
        }

        response.hasMore = false;

        return response;
    }

    async uploadMessage(data) {
        await this.prepare();

        let path = [].concat(data.path || []).join('/');

        let targetFolder = await this.resolveFolder(path);
        if (!targetFolder) {
            let error = new Error('Upload failed');
            error.info = {
                response: 'Not able to find mailbox folder'
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }

        let { raw, messageId, referencedMessage, documentStoreUsed } = await this.prepareRawMessage(data);
        if (raw?.buffer) {
            // convert from a Uint8Array to a Buffer
            raw = Buffer.from(raw);
        }

        let messageData;
        try {
            messageData = await this.request(`${OUTLOOK_API_BASE}/me/messages`, 'post', Buffer.from(raw.toString('base64')), {
                contentType: 'text/plain'
            });
        } catch (err) {
            switch (err.oauthRequest?.status) {
                case 400: {
                    let error = new Error('Invalid message format');
                    error.info = {
                        response: err.oauthRequest?.response?.error?.message || `Invalid message format`
                    };
                    error.code = err.oauthRequest?.response?.error?.code || 'InvalidMessage';
                    error.statusCode = 500; // do not retry sending
                    throw error;
                }

                default:
                    this.logger.error({
                        msg: 'Failed to upload message',
                        messageId,
                        err
                    });
                    throw err;
            }
        }

        if (messageData && messageData.parentFolderId !== targetFolder.id) {
            // move from Drafts to actual folder
            try {
                messageData = await this.request(`${OUTLOOK_API_BASE}/me/messages/${messageData.id}/move`, 'post', {
                    destinationId: targetFolder.id
                });
                if (!messageData) {
                    throw new Error('Failed to move message to target folder');
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to move message to target folder',
                    messageId,
                    err
                });
                throw err;
            }
        }

        let response = {
            message: messageData?.id,
            path: targetFolder.pathName,
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

        return response;
    }

    async submitMessage(data) {
        await this.prepare();
        let { raw, messageId, queueId, job: jobData } = data;

        if (raw?.buffer) {
            // convert from a Uint8Array to a Buffer
            raw = Buffer.from(raw);
        }

        const submitJobEntry = await this.submitQueue.getJob(jobData.id);
        if (!submitJobEntry) {
            // already failed?
            this.logger.error({
                msg: 'Submit job was not found',
                job: jobData.id
            });
            return false;
        }

        try {
            // returns nothing, throws if fails
            await this.request(`${OUTLOOK_API_BASE}/me/sendMail`, 'post', Buffer.from(raw.toString('base64')), {
                contentType: 'text/plain',
                returnText: true
            });
        } catch (err) {
            switch (err.oauthRequest?.status) {
                case 400: {
                    let error = new Error('Invalid message format');
                    error.info = {
                        response: err.oauthRequest?.response?.error?.message || `Invalid message format`
                    };
                    error.code = err.oauthRequest?.response?.error?.code || 'InvalidMessage';
                    error.statusCode = 500; // do not retry sending
                    throw error;
                }

                default:
                    this.logger.error({
                        msg: 'Failed to submit message',
                        messageId,
                        err
                    });
                    throw err;
            }
        }

        try {
            // try to update
            await submitJobEntry.updateProgress({
                status: 'smtp-completed',
                messageId,
                originalMessageId: messageId
            });
        } catch (err) {
            // ignore
        }

        await this.notify(false, EMAIL_SENT_NOTIFY, {
            messageId,
            originalMessageId: messageId,
            queueId
        });

        if (data.feedbackKey) {
            await this.redis
                .multi()
                .hset(data.feedbackKey, 'success', 'true')
                .expire(1 * 60 * 60);
        }

        return {
            messageId
        };
    }

    async createMailbox(path) {
        await this.prepare();

        path = [].concat(path || []).join('/');

        let subPaths = path.split('/');

        let displayName = subPaths.pop();
        let parentPath = subPaths.join('/');

        let parentFolder;
        if (parentPath) {
            parentFolder = await this.resolveFolder(parentPath);
            if (!parentFolder) {
                let error = new Error('Create failed');
                error.info = {
                    response: 'Not able to find parent folder'
                };
                error.code = 'NotFound';
                error.statusCode = 404;
                throw error;
            }
        }

        let reqUrl;
        if (parentFolder) {
            // child folder
            reqUrl = `${OUTLOOK_API_BASE}/me/mailFolders/${parentFolder.id}/childFolders`;
        } else {
            // root folder
            reqUrl = `${OUTLOOK_API_BASE}/me/mailFolders`;
        }

        let mailbox;
        try {
            mailbox = await this.request(reqUrl, 'post', {
                displayName,
                isHidden: false
            });
            if (!mailbox) {
                throw new Error('Failed to create mailbox');
            }
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 'ErrorFolderExists':
                    // already exists
                    return {
                        path,
                        created: false
                    };

                default: {
                    let error = new Error('Create failed');
                    error.info = {
                        response: err?.oauthRequest?.response?.error?.message
                    };
                    error.code = err?.oauthRequest?.response?.error?.code;
                    error.statusCode = 400;
                    throw error;
                }
            }
        }

        setImmediate(() => {
            // refresh mailbox listing cache after changes
            this.listMailboxes().catch(err => {
                this.logger.error({ msg: 'Failed to list mailboxes', err });
            });
        });

        return {
            mailboxId: mailbox.id,
            path: []
                .concat(parentFolder?.path || [])
                .concat(mailbox.displayName)
                .join('/'),
            created: true
        };
    }

    async renameMailbox(path, newPath) {
        await this.prepare();

        path = [].concat(path || []).join('/');
        newPath = [].concat(newPath || []).join('/');

        let sourceFolder = await this.resolveFolder(path);
        if (!sourceFolder) {
            let error = new Error('Rename failed');
            error.info = {
                response: 'Not able to find mailbox folder'
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }

        let sourceParts = sourceFolder.pathName.split('/');
        let sourceName = sourceParts.pop();
        let sourceParentPath = sourceParts.join('/');

        let destinationFolder = await this.resolveFolder(newPath, { pathNameOnly: true });

        let destinationParts = destinationFolder.pathName.split('/');
        let destinationName = destinationParts.pop();
        let destinationParentPath = destinationParts.join('/');

        let destinationParentFolder;
        if (sourceParentPath !== destinationParentPath) {
            destinationParentFolder = await this.resolveFolder(destinationParentPath);
        }

        // Step 1. Rename
        if (sourceName !== destinationName) {
            let mailbox;
            try {
                mailbox = await this.request(`${OUTLOOK_API_BASE}/me/mailFolders/${sourceFolder.id}`, 'patch', {
                    displayName: destinationName
                });
                if (!mailbox) {
                    throw new Error('Failed to rename mailbox');
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to rename folder',
                    mailboxId: sourceFolder.id,
                    path: sourceFolder.pathName,
                    newPath: destinationFolder.pathName,
                    err
                });
                throw err;
            }
        }

        // Step 2. Move
        if (destinationParentFolder) {
            let mailbox;
            try {
                mailbox = await this.request(`${OUTLOOK_API_BASE}/me/mailFolders/${sourceFolder.id}/move`, 'post', {
                    destinationId: destinationParentFolder.id
                });
                if (!mailbox) {
                    throw new Error('Failed to move mailbox');
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to move folder',
                    mailboxId: sourceFolder.id,
                    path: sourceFolder.pathName,
                    newPath: destinationFolder.pathName,
                    err
                });
                throw err;
            }
        }

        setImmediate(() => {
            // refresh mailbox listing cache after changes
            this.listMailboxes().catch(err => {
                this.logger.error({ msg: 'Failed to list mailboxes', err });
            });
        });

        return {
            mailboxId: sourceFolder.id,
            path: sourceFolder.pathName,
            newPath: destinationFolder.pathName,
            renamed: true
        };
    }

    async deleteMailbox(path) {
        await this.prepare();

        path = [].concat(path || []).join('/');

        let folder = await this.resolveFolder(path);
        if (!folder) {
            let error = new Error('Delete failed');
            error.info = {
                response: 'Not able to find mailbox folder'
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }

        try {
            await this.request(`${OUTLOOK_API_BASE}/me/mailFolders/${folder.id}`, 'delete', Buffer.alloc(0), { returnText: true });
        } catch (err) {
            this.logger.error({
                msg: 'Failed to delete folder',
                mailboxId: folder.id,
                path: folder.pathName,
                err
            });
            throw err;
        }

        setImmediate(() => {
            // refresh mailbox listing cache after changes
            this.listMailboxes().catch(err => {
                this.logger.error({ msg: 'Failed to list mailboxes', err });
            });
        });

        return {
            mailboxId: folder.id,
            path: folder.pathName,
            deleted: true
        };
    }

    // PRIVATE METHODS

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getAccountCacheKey() {
        return `${REDIS_PREFIX}iac:${this.account}`;
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

    async getClient(force) {
        if (this.oAuth2Client && !force) {
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

    // This is needed to check if there has been any changes in mailbox folder structure.
    // If a mailbox folder is added or removed, then the delta will change, so we should not use
    // cached mailbox listing and instead, generate a new listing
    async renewMailboxFolderCache() {
        // cache last known mailbox change
        let deltaReqUrl = (await this.redis.hget(this.getAccountKey(), 'outlookMailFoldersDeltaUrl')) || `${OUTLOOK_API_BASE}/me/mailFolders/delta`;

        let hasChanges = false;

        let deltaCheckDone = false;
        while (!deltaCheckDone) {
            let deltaRes;

            try {
                deltaRes = await this.request(deltaReqUrl);
            } catch (err) {
                this.logger.error({ msg: 'Failed to check mailbox folder delta', err });
                // might be faulty entry, so clear it
                await this.redis.hdel(this.getAccountKey(), 'outlookMailFoldersDeltaUrl');

                return true;
            }

            if (deltaRes.value?.length) {
                hasChanges = true;
            }

            if (deltaRes['@odata.nextLink']) {
                deltaReqUrl = deltaRes['@odata.nextLink'];
                await this.redis.hSetExists(this.getAccountKey(), 'outlookMailFoldersDeltaUrl', deltaReqUrl);
            } else {
                deltaCheckDone = true;
                if (deltaRes['@odata.deltaLink']) {
                    deltaReqUrl = deltaRes['@odata.deltaLink'];
                    await this.redis.hSetExists(this.getAccountKey(), 'outlookMailFoldersDeltaUrl', deltaReqUrl);
                }
            }
        }

        return hasChanges;
    }

    async getCachedMailboxListing() {
        let cachedListing;
        let cachedListingValue = await this.redis.hget(this.getAccountCacheKey(), 'outlookMailboxListing');
        if (cachedListingValue) {
            try {
                cachedListing = JSON.parse(cachedListingValue);
            } catch (err) {
                this.logger.error({ msg: 'Failed to parse cached mailbox listing', err });
            }
        }
        return cachedListing;
    }

    async getMailboxListing() {
        let specialTags = new Map([
            ['deleteditems', '\\Trash'],
            ['drafts', '\\Drafts'],
            ['inbox', '\\Inbox'],
            ['junkemail', '\\Junk'],
            ['sentitems', '\\Sent']
        ]);

        let specialUseKeys = Array.from(specialTags.keys());
        let specialUseTagIds = new Map();

        for (let specialUseKey of specialUseKeys) {
            // Use caching. Assuming that the ID of the special-use folder does not change, even if the display name does
            let cachedValue;
            let cachedValueStr = await this.redis.hget(this.getAccountCacheKey(), `outlookMailbox:${specialUseKey}`);
            if (cachedValueStr) {
                try {
                    cachedValue = JSON.parse(cachedValueStr);
                } catch (err) {
                    await this.redis.hdel(this.getAccountCacheKey(), `outlookMailbox:${specialUseKey}`);
                }
            }

            if (cachedValue) {
                specialUseTagIds.set(cachedValue.id, specialTags.get(specialUseKey));
                continue;
            }

            let reqUrl = `${OUTLOOK_API_BASE}/me/mailFolders/${specialUseKey}`;
            try {
                let mailbox = await this.request(reqUrl);
                if (mailbox) {
                    await this.redis.hset(this.getAccountCacheKey(), `outlookMailbox:${specialUseKey}`, JSON.stringify(mailbox));
                    specialUseTagIds.set(mailbox.id, specialTags.get(specialUseKey));
                }
            } catch (err) {
                this.logger.error({ msg: 'Failed to resolve mailbox for special use key', specialUseKey, err });
            }
        }

        let mailboxListing = [];

        let traverse = async (pathNamePrefix, folderId) => {
            let list = [];
            let done = false;
            let reqUrl = `${OUTLOOK_API_BASE}/me/mailFolders${folderId ? `/${folderId}/childFolders` : ''}`;
            while (!done) {
                let mailboxRes = await this.request(reqUrl);
                if (mailboxRes.value) {
                    list.push(
                        ...mailboxRes.value.map(entry => {
                            if (!folderId) {
                                entry.rootFolder = true;
                            }
                            let specialUse = specialUseTagIds.get(entry.id);
                            if (specialUse) {
                                entry.specialUse = specialUse;
                            }
                            if (pathNamePrefix) {
                                entry.parentPath = pathNamePrefix;
                            }
                            entry.pathName = `${pathNamePrefix ? `${pathNamePrefix}/` : ''}${entry.displayName}`;
                            return entry;
                        })
                    );
                }
                if (!mailboxRes['@odata.nextLink']) {
                    done = true;
                } else {
                    reqUrl = mailboxRes['@odata.nextLink'];
                }
            }

            mailboxListing.push(...list);

            for (let entry of list) {
                // do not traverse subfolders for folders with a slash in the name
                if (entry.childFolderCount && entry.displayName.indexOf('/') < 0) {
                    await traverse(entry.pathName, entry.id);
                }
            }
        };

        await traverse();

        // keep only real folders and folders that do not contain slash in the name
        mailboxListing = mailboxListing.filter(
            entry => (!entry['@odata.type'] || /^#?microsoft\.graph\.mailFolder$/.test(entry['@odata.type'])) && entry.displayName.indexOf('/') < 0
        );

        return mailboxListing;
    }

    async resolveFolder(path, options) {
        options = options || {};

        let cachedListing = await this.getCachedMailboxListing();
        let mailboxListing = cachedListing || (await this.getMailboxListing());

        if (options.byId) {
            return mailboxListing.find(entry => entry.id === path);
        }

        let specialUseTags = new Map([
            ['\\Trash', 'deleteditems'],
            ['\\Drafts', 'drafts'],
            ['\\Inbox', 'inbox'],
            ['\\Junk', 'junkemail'],
            ['\\Sent', 'sentitems']
        ]);

        if (/^inbox$/i.test(path)) {
            path = '\\Inbox';
        }

        if (specialUseTags.has(path)) {
            // resolve special use tag folder
            let folderEntry = mailboxListing.find(entry => entry.specialUse === path);
            if (folderEntry) {
                return folderEntry;
            }
        }

        let pathParts = path.split('/');
        if (/^inbox$/i.test(pathParts[0])) {
            let inboxFolder = mailboxListing.find(entry => entry.specialUse === '\\Inbox');
            if (inboxFolder) {
                pathParts[0] = inboxFolder.path;
            }
        }
        path = pathParts.join('/');

        if (options.pathNameOnly) {
            return { pathName: path };
        }

        let folderEntry = mailboxListing.find(entry => entry.pathName === path);

        return folderEntry;
    }

    formatMessage(messageData, options) {
        let { extended, path, textType, showPath } = options || {};

        let date = messageData.receivedDateTime ? new Date(messageData.receivedDateTime) : undefined;
        if (date?.toString() === 'Invalid Date') {
            date = undefined;
        }

        const flags = [];
        if (messageData.isRead) {
            flags.push('\\Seen');
        }
        if (messageData.isDraft) {
            flags.push('\\Draft');
        }
        if (messageData.flag?.flagStatus === 'flagged') {
            flags.push('\\Flagged');
        }

        let encodedTextSize = {};
        let textContents = {};

        // set defaults for requested text type
        if (textType && textType !== '*') {
            textContents[options.textType] = '';
            encodedTextSize[options.textType] = 0;
        }

        if (messageData?.body?.contentType) {
            let textContent = messageData.body.content || '';
            encodedTextSize[messageData.body.contentType] = Buffer.byteLength(textContent);
            if ([messageData?.body?.contentType, '*'].includes(textType)) {
                textContents[messageData.body.contentType] = textContent;
            }
        }

        let message = {
            id: messageData.id,

            path: ((extended || showPath) && path) || undefined,

            emailId: messageData.id,
            threadId: messageData.conversationId || undefined,

            date: date ? date.toISOString() : undefined,

            flags,

            unseen: !flags.includes('\\Seen') ? true : undefined,
            flagged: flags.includes('\\Flagged') ? true : undefined,
            draft: flags.includes('\\Draft') ? true : undefined,

            subject: messageData.subject || undefined,
            from: messageData.from?.emailAddress || undefined,

            replyTo: messageData.replyTo?.length ? messageData.replyTo.map(entry => entry.emailAddress).filter(entry => entry) : undefined,
            sender: (extended && messageData.sender?.emailAddress) || undefined,

            to: messageData.toRecipients?.length ? messageData.toRecipients.map(entry => entry.emailAddress).filter(entry => entry) : undefined,
            cc: messageData.ccRecipients?.length ? messageData.ccRecipients.map(entry => entry.emailAddress).filter(entry => entry) : undefined,
            bcc: extended && messageData.bccRecipients?.length ? messageData.bccRecipients.map(entry => entry.emailAddress).filter(entry => entry) : undefined,

            messageId: messageData.internetMessageId,

            text: {
                id: messageData.id,
                encodedSize: encodedTextSize,
                plain: textContents?.plain?.toString(),
                html: textContents?.html?.toString(),
                hasMore: textContents?.plain || textContents?.html ? false : undefined
            },

            preview: messageData.bodyPreview
        };

        if (messageData.internetMessageHeaders) {
            let headers = {};
            for (let header of messageData?.internetMessageHeaders || []) {
                let { name, value } = header;
                name = (name || '').toString().trim().toLowerCase();
                value = (value || '').toString().trim();
                if (!(name in headers)) {
                    headers[name] = [];
                }
                if (!Array.isArray(headers[name])) {
                    continue;
                }
                headers[name].push(value);

                switch (name) {
                    case 'in-reply-to': {
                        message.inReplyTo = value;
                        break;
                    }
                }
            }
            message.headers = headers;

            if (this.isAutoreply(message)) {
                message.isAutoReply = true;
            }
        }

        if (messageData.attachments?.length) {
            message.attachments = messageData.attachments.map(entry => {
                const attachment = {
                    id: msgpack.encode([messageData.id, entry.id]).toString('base64url'),
                    contentType: entry.contentType,
                    encodedSize: entry.size,
                    inline: !!entry.isInline
                };

                if (entry.name) {
                    attachment.filename = entry.name;
                }

                if (entry.contentId) {
                    attachment.contentId = entry.contentId.replace(/^<*/, '<').replace(/>*$/, '>');
                    if (textContents?.html?.indexOf(`cid:${attachment.contentId.replace(/^[\s<]*|[\s>]*$/g, '')}`) >= 0) {
                        attachment.embedded = true;
                    }
                }

                return attachment;
            });
        }

        return message;
    }

    async getAttachmentContent(attachmentId) {
        const [messageId, id] = msgpack.decode(Buffer.from(attachmentId, 'base64url'));

        await this.prepare();

        let attachmentResponse;

        try {
            attachmentResponse = await this.request(`${OUTLOOK_API_BASE}/me/messages/${messageId}/attachments/${id}`);
        } catch (err) {
            switch (err.oauthRequest?.status) {
                case 404: {
                    let error = new Error('Unknown attachment');
                    error.info = {
                        response: `Attachment does not exist`
                    };
                    error.code = 'NotFound';
                    error.statusCode = 404;
                    throw error;
                }

                case 400: {
                    let error = new Error('Invalid request');
                    error.info = {
                        response: err.oauthRequest?.response?.error?.message || `Invalid request`
                    };
                    error.code = err.oauthRequest?.response?.error?.code || 'InvalidRequest';
                    error.statusCode = 400;
                    throw error;
                }

                default:
                    this.logger.error({
                        msg: 'Failed to fetch attachment',
                        messageId,
                        err
                    });
                    throw err;
            }
        }

        return {
            content: attachmentResponse?.contentBytes ? Buffer.from(attachmentResponse?.contentBytes, 'base64') : null,
            contentType: attachmentResponse?.contentType,
            filename: attachmentResponse?.name
        };
    }

    // convert IMAP SEARCH query object to a Gmail API search query
    prepareQuery(search) {
        search = search || {};

        const filterParts = [];

        const disabledKeys = [
            'seq',
            'uid',
            'paths',
            'answered',
            'deleted',
            'modseq',

            //
            'to',
            'cc',
            'bcc',
            'larger',
            'smaller'
        ];

        // not supported search terms
        for (let disabledKey of disabledKeys) {
            if (disabledKey in search) {
                let error = new Error(`Unsupported search term "${disabledKey}"`);
                error.code = 'UnsupportedSearchTerm';
                error.statusCode = 400;
                throw error;
            }
        }

        // unseen
        if (typeof search.unseen === 'boolean') {
            filterParts.push(`isRead eq ${search.unseen ? 'false' : 'true'}`);
        }

        // seen
        if (typeof search.seen === 'boolean') {
            filterParts.push(`isRead eq ${search.seen ? 'true' : 'false'}`);
        }

        // draft
        if (typeof search.draft === 'boolean') {
            filterParts.push(`isDraft eq ${search.draft ? 'true' : 'false'}`);
        }

        // flagged
        if (typeof search.flagged === 'boolean') {
            filterParts.push(`flag/flagStatus eq '${search.flagged ? 'flagged' : 'notFlagged'}'`);
        }

        // from
        if (search.from) {
            filterParts.push(
                `(from/emailAddress/address eq ${this.formatSearchTerm(search.from)} or contains(from/emailAddress/name, ${this.formatSearchTerm(
                    search.from
                )}))`
            );
        }

        if (search.subject) {
            filterParts.push(`contains(subject, ${this.formatSearchTerm(search.subject)})`);
        }

        if (search.body) {
            filterParts.push(`contains(body/content, ${this.formatSearchTerm(search.body)})`);
        }

        if (search.emailId) {
            filterParts.push(`id eq ${this.formatSearchTerm(search.emailId)}`);
        }

        if (search.threadId) {
            filterParts.push(`conversationId eq ${this.formatSearchTerm(search.threadId)}`);
        }

        if (search.before || search.sentBefore) {
            filterParts.push(`receivedDateTime lt ${this.formatSearchTerm(search.before || search.sentBefore, false)}`);
        }

        if (search.since || search.sentSince) {
            filterParts.push(`receivedDateTime gt ${this.formatSearchTerm(search.since || search.sentSince, false)}`);
        }

        for (let headerKey of Object.keys(search.header || {})) {
            switch (headerKey.toLowerCase().trim()) {
                case 'message-id':
                    filterParts.push(`internetMessageId eq ${this.formatSearchTerm(search.header[headerKey])}`);
                    break;
                default: {
                    let error = new Error(`Unsupported search header "${headerKey}"`);
                    error.code = 'UnsupportedSearchTerm';
                    error.statusCode = 400;
                    throw error;
                }
            }
        }

        return {
            $filter: filterParts.join(' and ').trim()
        };
    }

    formatSearchTerm(term, quot = "'") {
        if (typeof term === 'object' && term && Object.prototype.toString.apply(new Date()) === '[object Date]') {
            term = term.toISOString();
        }

        term = (term || '')
            .toString()
            .replace(/[\s"]+/g, ' ')
            .trim();

        if (quot === "'") {
            term = term.replace(/'/g, "''");
        }

        return `${quot ? quot : ''}${term}${quot ? quot : ''}`;
    }

    decodeCursorStr(cursorStr) {
        let type = 'ms';

        if (cursorStr) {
            let splitPos = cursorStr.indexOf('_');
            if (splitPos >= 0) {
                let cursorType = cursorStr.substring(0, splitPos);
                cursorStr = cursorStr.substring(splitPos + 1);
                if (cursorType && type !== cursorType) {
                    let error = new Error('Invalid cursor');
                    error.code = 'InvalidCursorType';
                    throw error;
                }
            }

            try {
                let { page: cursorPage } = JSON.parse(Buffer.from(cursorStr, 'base64url'));
                if (typeof cursorPage === 'number' && cursorPage >= 0) {
                    return cursorPage;
                }
            } catch (err) {
                this.logger.error({ msg: 'Cursor parsing error', cursorStr, err });

                let error = new Error('Invalid paging cursor');
                error.code = 'InvalidCursorValue';
                error.statusCode = 400;
                throw error;
            }
        }

        return null;
    }

    encodeCursorString(cursorPage) {
        if (typeof cursorPage !== 'number' || cursorPage < 0) {
            return null;
        }
        cursorPage = cursorPage || 0;
        let type = 'ms';
        return `${type}_${Buffer.from(JSON.stringify({ page: cursorPage })).toString('base64url')}`;
    }
}

module.exports = { OutlookClient };
