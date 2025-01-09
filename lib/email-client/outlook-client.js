'use strict';

const { BaseClient } = require('./base-client');
const { Account } = require('../account');
const settings = require('../settings');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const msgpack = require('msgpack5')();
const he = require('he');
const { emitChangeEvent } = require('../tools');
const { mimeHtml } = require('@postalsys/email-text-tools');
const crypto = require('crypto');
const { Gateway } = require('../gateway');
const { detectMimeType, detectExtension } = require('nodemailer/lib/mime-funcs/mime-types');

const {
    REDIS_PREFIX,
    AUTH_ERROR_NOTIFY,
    AUTH_SUCCESS_NOTIFY,
    EMAIL_SENT_NOTIFY,
    OUTLOOK_EXPIRATION_TIME,
    OUTLOOK_EXPIRATION_RENEW_TIME,
    MESSAGE_UPDATED_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_MISSING_NOTIFY
} = require('../consts');

const MAX_BATCH_SIZE = 20;

// Subscription is renewed automatically. But just in case, check once in an hour
const RENEW_WATCH_TTL = 60 * 60 * 1000; // 1h

/*
✅ listMessages
  ✅ paging - cursor + page nr
  ✅ search queries - no support for to/cc/bcc queries
✅ getText
✅ getMessage
✅ updateMessage
✅ updateMessages - not supported, throws
✅ listMailboxes
✅ moveMessage
🟡 moveMessages - not supported, throws
✅ deleteMessage 
✅ deleteMessages - not supported, throws
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

        this.oauth2UserPath = 'me'; // `users/${encodeURIComponent('shared@example.com')}`;

        this.processingHistory = null;
        this.renewWatchTimer = null;
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

            let apiUrl = /^https:/.test(url) ? url : new URL(`/v1.0${url}`, this.oAuth2Client.apiBase).href;

            result = await this.oAuth2Client.request(accessToken, apiUrl, method, payload, options);
        } catch (err) {
            switch (err.oauthRequest?.response?.error?.code) {
                case 'ErrorExecuteSearchStaleData': {
                    this.logger.error({ msg: 'Invalid or expired paging cursor', account: this.account, err });
                    let error = new Error('Invalid or expired paging cursor');
                    error.code = 'InvalidPagingCursor';
                    error.statusCode = err.oauthRequest?.status || 500;
                    throw error;
                }
            }

            switch (err.oauthRequest?.status) {
                case 401:
                    this.logger.error({ msg: 'Failed to authenticate API request', account: this.account, accessToken, err });
                    throw err;

                case 429:
                    this.logger.error({ msg: 'API request was throttled', account: this.account, err });
                    throw err;

                default:
                    this.logger.error({ msg: 'Failed to run API request', account: this.account, err });
                    throw err;
            }
        }

        return result;
    }

    // PUBLIC METHODS

    async init() {
        await this.getAccount();
        await this.prepareDelegatedAccount();
        await this.getClient(true);

        let accountData = await this.accountObject.loadAccountData();

        let profileRes;
        try {
            profileRes = await this.request(`/${this.oauth2UserPath}`);
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

        await this.redis.hdel(this.getAccountKey(), 'lastErrorState', 'lastError:errorCount', 'lastError:first');
        await emitChangeEvent(this.logger, this.account, 'state', this.state);

        // additional operations

        await this.ensureSubscription();
        this.setupRenewWatchTimer();

        try {
            await this.listMailboxes();
        } catch (err) {
            this.logger.error({ msg: 'Failed to renew mailbox folder cache', err });
        }

        this.triggerSync();
    }

    async close() {
        clearTimeout(this.renewWatchTimer);
        this.closed = true;

        if (['init', 'connecting', 'syncing', 'connected'].includes(this.state)) {
            this.state = 'disconnected';
            await this.setStateVal();
            await emitChangeEvent(this.logger, this.account, 'state', this.state);
        }

        return null;
    }

    async currentState() {
        return (await this.redis.hget(this.getAccountKey(), 'state')) || 'disconnected';
    }

    async delete() {
        clearTimeout(this.renewWatchTimer);
        this.closed = true;

        if (['init', 'connecting', 'syncing', 'connected'].includes(this.state)) {
            this.state = 'disconnected';
            await this.setStateVal();
            await emitChangeEvent(this.logger, this.account, 'state', this.state);
        }

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

    async listMessages(query, options) {
        options = options || {};

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
        let $skiptoken;

        if (query.cursor) {
            let { cursorPage, skipToken } = this.decodeCursorStr(query.cursor);
            if (typeof cursorPage === 'number' && cursorPage >= 0) {
                page = cursorPage;
            }
            if (skipToken) {
                $skiptoken = skipToken;
            }
        }

        let requestQuery = {
            $count: true,
            $top: pageSize,
            $skip: page * pageSize,
            $skiptoken,
            $orderBy: 'receivedDateTime desc',
            $select: (options.metadataOnly
                ? ['id', 'conversationId', 'receivedDateTime', 'isRead', 'isDraft', 'flag', 'body', 'subject', 'from', 'replyTo', 'sender', 'internetMessageId']
                : [
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
            )
                .concat(!folder ? 'parentFolderId' : [])
                .join(','),
            $expand: options.metadataOnly ? undefined : 'attachments($select=id,name,contentType,size,isInline,microsoft.graph.fileAttachment/contentId)'
        };

        let useOutlookSearch = false;
        let skipToken = null;

        if (query.search) {
            if (query.useOutlookSearch) {
                const $search = this.prepareSearchQuery(query.search);
                if ($search) {
                    requestQuery.$search = `"${$search}"`;
                    // remove unsupported request arguments
                    for (let disabledParam of ['$skip', '$orderBy', '$count']) {
                        delete requestQuery[disabledParam];
                    }
                    useOutlookSearch = true;
                }
            } else {
                const $filter = this.prepareFilterQuery(query.search);
                if ($filter) {
                    // we need to have receivedDateTime as the first filtering property, otherwise ordering will fail
                    requestQuery.$filter = `receivedDateTime gt 1970-01-01T00:00:00.000Z and ${$filter}`;
                }
            }
        }

        let messages = [];
        let totalMessages;

        // list messages
        try {
            let listing = await this.request(`/${this.oauth2UserPath}/${folder ? `mailFolders/${folder.id}/` : ''}messages`, 'get', requestQuery);

            totalMessages = !isNaN(listing['@odata.count']) ? Number(listing['@odata.count']) : undefined;

            if (useOutlookSearch && listing['@odata.nextLink']) {
                let nextLinkObj = new URL(listing['@odata.nextLink']);
                skipToken = nextLinkObj.searchParams.get('$skiptoken');
            }

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

        let pages = typeof totalMessages === 'number' ? Math.ceil(totalMessages / pageSize) || 1 : undefined;

        if (page < 0) {
            page = 0;
        }

        let nextPageCursor = page < pages - 1 || skipToken ? this.encodeCursorString(page + 1, skipToken) : null;
        // no previous page cursor if we are using skip token for paging
        let prevPageCursor = skipToken ? undefined : page > 0 ? this.encodeCursorString(Math.min(page - 1, pages - 1)) : null;

        return {
            total: totalMessages,
            page,
            pages,
            nextPageCursor,
            prevPageCursor,
            messages
        };
    }

    async getRawMessage(emailId) {
        await this.prepare();

        let raw;

        try {
            raw = await this.request(`/${this.oauth2UserPath}/messages/${emailId}/$value`, 'get', Buffer.alloc(0), { returnText: true });
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
                        emailId,
                        err
                    });
                    throw err;
            }
        }

        return raw ? Buffer.from(raw) : null;
    }

    async deleteMessage(emailId, force) {
        await this.prepare();

        if (force) {
            try {
                await this.request(`/${this.oauth2UserPath}/messages/${emailId}`, 'delete', Buffer.alloc(0), { returnText: true });
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to delete message',
                    emailId,
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
            messageData = await this.request(`/${this.oauth2UserPath}/messages/${emailId}/move`, 'post', {
                destinationId: 'deleteditems'
            });
            if (!messageData) {
                throw new Error('Failed to move message to Trash');
            }
        } catch (err) {
            this.logger.error({
                msg: 'Failed to move message to Trash',
                emailId,
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
                emailId,
                err
            });
        }

        return {
            deleted: true,
            moved: {
                destination: folder?.pathName,
                message: emailId
            }
        };
    }

    async deleteMessages(path, search, force) {
        await this.prepare();

        let folder;
        if (!force) {
            try {
                folder = await this.resolveFolder('\\Trash');
                if (!force && folder?.specialUse === '\\Trash') {
                    force = true;
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to resolve folder for Trash',
                    err
                });
            }
        }

        // Step 1. Resolve matching messages
        let emailIds = await this.searchEmailIds(path, search);

        if (!emailIds?.length) {
            // nothing to do here
            return { deleted: false };
        }

        let batch = [];
        let idGen = 0;
        let updatedEmailIds = [];
        let messageMap = new Map();

        let submitBatch = async () => {
            let responseData;
            try {
                responseData = await this.request(`/$batch`, 'post', {
                    requests: batch
                });
                for (let response of responseData?.responses || []) {
                    if (response?.status >= 200 && response?.status < 300) {
                        let emailId = messageMap.get(response.id);
                        if (emailId) {
                            updatedEmailIds.push(emailId);
                        }
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to run batch operation',
                    err
                });
                throw err;
            } finally {
                batch = [];
                messageMap = new Map();
            }
        };

        let formatRequest = emailId => {
            let reqId = `msg_${++idGen}`;
            messageMap.set(reqId, emailId);

            if (force) {
                return {
                    id: reqId,
                    method: 'DELETE',
                    url: `/${this.oauth2UserPath}/messages/${emailId}`
                };
            } else {
                return {
                    id: reqId,
                    method: 'POST',
                    url: `/${this.oauth2UserPath}/messages/${emailId}/move`,
                    body: { destinationId: 'deleteditems' },
                    headers: {
                        'Content-Type': 'application/json'
                    }
                };
            }
        };

        for (let emailId of emailIds) {
            batch.push(formatRequest(emailId));
            // submit batch
            if (batch.length >= MAX_BATCH_SIZE) {
                await submitBatch(batch);
            }
        }
        if (batch.length) {
            // submit batch
            await submitBatch(batch);
        }

        return Object.assign(
            { deleted: true },
            !force
                ? {
                      moved: {
                          destination: folder.pathName,
                          emailIds: updatedEmailIds
                      }
                  }
                : {
                      deletedMessages: {
                          emailIds: updatedEmailIds
                      }
                  }
        );
    }

    // MS Graph API allows to manage only \Seen and \Flagged
    async updateMessage(emailId, updates) {
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
            modifyResult = await this.request(`/${this.oauth2UserPath}/messages/${emailId}`, 'patch', flagUpdates);
        } catch (err) {
            this.logger.error({
                msg: 'Failed to update message',
                emailId,
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

    async updateMessages(path, search, updates) {
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

        // Step 1. Resolve matching messages
        let emailIds = await this.searchEmailIds(path, search);

        if (!emailIds?.length) {
            // nothing to do here
            return updates;
        }

        let batch = [];
        let idGen = 0;
        let updatedEmailIds = [];
        let messageMap = new Map();

        let submitBatch = async () => {
            let responseData;
            try {
                responseData = await this.request(`/$batch`, 'post', {
                    requests: batch
                });
                for (let response of responseData?.responses || []) {
                    if (response?.status >= 200 && response?.status < 300) {
                        let emailId = messageMap.get(response.id);
                        if (emailId) {
                            updatedEmailIds.push(emailId);
                        }
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to run batch operation',
                    err
                });
                throw err;
            } finally {
                batch = [];
                messageMap = new Map();
            }
        };

        let formatRequest = emailId => {
            let reqId = `msg_${++idGen}`;
            messageMap.set(reqId, emailId);
            return {
                id: reqId,
                method: 'PATCH',
                url: `/${this.oauth2UserPath}/messages/${emailId}`,
                body: flagUpdates,
                headers: {
                    'Content-Type': 'application/json'
                }
            };
        };

        for (let emailId of emailIds) {
            batch.push(formatRequest(emailId));
            // submit batch
            if (batch.length >= MAX_BATCH_SIZE) {
                await submitBatch(batch);
            }
        }
        if (batch.length) {
            // submit batch
            await submitBatch(batch);
        }

        return Object.assign({}, updates, { emailIds: updatedEmailIds });
    }

    async moveMessage(emailId, target) {
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
            messageData = await this.request(`/${this.oauth2UserPath}/messages/${emailId}/move`, 'post', {
                destinationId: targetFolder.id
            });
            if (!messageData) {
                throw new Error('Failed to move message');
            }
        } catch (err) {
            this.logger.error({
                msg: 'Failed to move message',
                emailId,
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

    async moveMessages(source, search, target) {
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

        // Step 1. Resolve matching messages
        let emailIds = await this.searchEmailIds(source, search);

        if (!emailIds?.length) {
            // nothing to do here
            return { path: targetFolder.pathName };
        }

        let batch = [];
        let idGen = 0;
        let updatedEmailIds = [];
        let messageMap = new Map();

        let submitBatch = async () => {
            let responseData;
            try {
                responseData = await this.request(`/$batch`, 'post', {
                    requests: batch
                });
                for (let response of responseData?.responses || []) {
                    if (response?.status >= 200 && response?.status < 300) {
                        let emailId = messageMap.get(response.id);
                        if (emailId) {
                            updatedEmailIds.push(emailId);
                        }
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to run batch operation',
                    err
                });
                throw err;
            } finally {
                batch = [];
                messageMap = new Map();
            }
        };

        let formatRequest = emailId => {
            let reqId = `msg_${++idGen}`;
            messageMap.set(reqId, emailId);
            return {
                id: reqId,
                method: 'POST',
                url: `/${this.oauth2UserPath}/messages/${emailId}/move`,
                body: { destinationId: targetFolder.id },
                headers: {
                    'Content-Type': 'application/json'
                }
            };
        };

        for (let emailId of emailIds) {
            batch.push(formatRequest(emailId));
            // submit batch
            if (batch.length >= MAX_BATCH_SIZE) {
                await submitBatch(batch);
            }
        }
        if (batch.length) {
            // submit batch
            await submitBatch(batch);
        }

        return Object.assign({ path: targetFolder.pathName }, { emailIds: updatedEmailIds });
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

        const contentResponse = {
            headers: {
                'content-type': attachmentData.mimeType || 'application/octet-stream',
                'content-disposition': 'attachment' + filenameParam
            },
            contentType: attachmentData.contentType,
            filename: attachmentData.filename,
            data: attachmentData.content
        };

        return contentResponse;
    }

    async getMessage(emailId, options) {
        options = options || {};

        if (options.webSafeHtml) {
            options.textType = '*';
            options.embedAttachedImages = true;
            options.preProcessHtml = true;
        }

        await this.prepare();

        let messageData, path, specialUse;

        try {
            messageData = await this.request(`/${this.oauth2UserPath}/messages/${emailId}`, 'get', {
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
                    'internetMessageHeaders',
                    'parentFolderId'
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
                        emailId,
                        err
                    });
                    throw err;
            }
        }

        // Microsoft Graph REST api 1.0 uses text and html, convert text to plain
        if (messageData.body?.contentType === 'text') {
            messageData.body.contentType = 'plain';
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
                        messageData.inReplyTo = value;
                        break;
                    }
                }
            }

            messageData.headers = headers;
        }

        const formattedMessage = this.formatMessage(messageData, {
            extended: true,
            path,
            textType: options.textType,
            showPath: options.showPath
        });

        if (options.embedAttachedImages && formattedMessage.text?.html && formattedMessage.attachments) {
            let attachmentMap = new Map();

            for (let attachment of formattedMessage.attachments) {
                let contentId = attachment.contentId && attachment.contentId.replace(/^<|>$/g, '');
                if (contentId && !attachmentMap.has(contentId) && formattedMessage.text.html.indexOf(`cid:${contentId}`) >= 0) {
                    attachmentMap.set(contentId, {
                        attachment,
                        content: await this.getAttachmentContent(attachment.id, {
                            returnBase64: true
                        })
                    });
                }
            }

            formattedMessage.text.html = formattedMessage.text.html.replace(/\bcid:([^"'\s>]+)/g, (fullMatch, cidMatch) => {
                if (attachmentMap.has(cidMatch)) {
                    let { content } = attachmentMap.get(cidMatch);
                    if (content.content) {
                        return `data:${content.contentType || 'application/octet-stream'};base64,${content.content}`;
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
            messageData = await this.request(`/${this.oauth2UserPath}/messages/${textId}`, 'get', {
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
                        emailId: textId,
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

    convertMessageToUploadObject(emailObject) {
        let messageUploadObj = {};

        for (let key of Object.keys(emailObject)) {
            switch (key) {
                case 'from':
                    messageUploadObj.from = {
                        emailAddress: {
                            address: emailObject.from.address
                        }
                    };
                    if (emailObject.from.name) {
                        messageUploadObj.from.emailAddress.name = emailObject.from.name;
                    }
                    break;

                case 'to':
                case 'cc':
                case 'bcc': {
                    let entryKey = `${key}Recipients`;
                    messageUploadObj[entryKey] = [];
                    for (let addressEntry of emailObject[key] || []) {
                        let addressObj = {
                            emailAddress: {
                                address: addressEntry.address
                            }
                        };
                        if (addressEntry.name) {
                            addressObj.emailAddress.name = addressEntry.name;
                        }
                        messageUploadObj[entryKey].push(addressObj);
                    }
                    break;
                }

                case 'subject':
                    messageUploadObj[key] = emailObject[key];
                    break;

                case 'headers': {
                    messageUploadObj.internetMessageHeaders = messageUploadObj.internetMessageHeaders || [];
                    for (let header of Object.keys(emailObject.headers)) {
                        messageUploadObj.internetMessageHeaders.push({
                            name: header.toLowerCase(),
                            value: emailObject.headers[header]
                        });
                    }
                    break;
                }

                case 'headerLines': {
                    messageUploadObj.internetMessageHeaders = messageUploadObj.internetMessageHeaders || [];
                    for (let i = emailObject.headerLines.length - 1; i >= 0; i--) {
                        let header = emailObject.headerLines[i];
                        if (
                            [
                                'date',
                                'content-transfer-encoding',
                                'from',
                                'to',
                                'cc',
                                'bcc',
                                'subject',
                                'mime-version',
                                'content-type',
                                'content-disposition',
                                'message-id',
                                'content-id'
                            ].includes(header.key) ||
                            // MS Graph API only allows up to 5 custom headers
                            messageUploadObj.internetMessageHeaders.length >= 5
                        ) {
                            continue;
                        }

                        let name = header.key;
                        let value = header.value ? header.substring(header.value.indexOf(':') + 1).trim() : '';
                        if (name && value) {
                            messageUploadObj.internetMessageHeaders.unshift({
                                name,
                                value
                            });
                        }
                    }
                    break;
                }

                case 'messageId':
                    messageUploadObj.internetMessageId = emailObject.messageId;
                    break;

                case 'attachments': {
                    messageUploadObj.attachments = [];
                    let attachmentCounter = 0;
                    for (let attachment of emailObject.attachments) {
                        let attachmentEntry = {
                            '@odata.type': '#microsoft.graph.fileAttachment'
                        };
                        if (attachment.filename) {
                            attachmentEntry.name = attachment.filename;
                        } else {
                            // generate a filename based on contentType as name is a required value
                            let ext = detectExtension(attachment.contentType);
                            attachmentEntry.name = `attachment_${++attachmentCounter}.${ext}`;
                        }

                        attachmentEntry.contentType = attachment.contentType || detectMimeType(attachment.filename) || 'application/octet-stream';
                        attachmentEntry.contentBytes = attachment.content;
                        if (attachment.cid) {
                            // make sure that cid links to not use <content-id> format, otherwise this will be replaced
                            attachmentEntry.contentId = attachment.cid.replace(/^[\s<]*|[\s>]*$/g, '');
                            if (emailObject.html?.indexOf(attachmentEntry.contentId) >= 0) {
                                attachmentEntry.isInline = true;
                                emailObject.html.replace(new RegExp(`cid:<${attachment.cid}>`, 'g'), `cid:${attachment.cid}`);
                            }
                        }
                        if (attachment.contentDisposition === 'inline') {
                            attachmentEntry.isInline = true;
                        }
                        messageUploadObj.attachments.push(attachmentEntry);
                    }
                    break;
                }
            }
        }

        if (emailObject.html) {
            messageUploadObj.body = {
                contentType: 'html',
                content: emailObject.html
            };
        } else if (emailObject.text) {
            messageUploadObj.body = {
                contentType: 'text',
                content: emailObject.text
            };
        }

        if (messageUploadObj.internetMessageHeaders && !messageUploadObj.internetMessageHeaders.length) {
            delete messageUploadObj.internetMessageHeaders;
        }

        return messageUploadObj;
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

        let { emailObject, messageId, referencedMessage, documentStoreUsed } = await this.prepareRawMessage(data, {
            returnObject: true
        });

        let messageUploadObj = this.convertMessageToUploadObject(emailObject);

        messageUploadObj.singleValueExtendedProperties = [];

        // https://learn.microsoft.com/en-us/office/client-developer/outlook/mapi/pidtagmessageflags-canonical-property
        // PR_MESSAGE_FLAGS
        if (data.flags) {
            let flagValue = 0;

            for (let flag of data.flags || []) {
                switch (flag) {
                    case '\\Seen': // mfRead, MSGFLAG_READ
                        flagValue |= 0x0001; // eslint-disable-line no-bitwise
                        break;
                    case '\\Draft': // mfUnsent, MSGFLAG_UNSENT
                        flagValue |= 0x0008; // eslint-disable-line no-bitwise
                        break;
                }
            }

            messageUploadObj.singleValueExtendedProperties.push({ id: 'Integer 0x0E07', value: flagValue.toString(10) });
        } else {
            messageUploadObj.singleValueExtendedProperties.push({ id: 'Integer 0x0E07', value: '0' });
        }

        // https://learn.microsoft.com/en-us/office/client-developer/outlook/mapi/pidtagmessagedeliverytime-canonical-property
        //PR_MESSAGE_DELIVERY_TIME
        if (data.internalDate) {
            messageUploadObj.singleValueExtendedProperties.push({ id: 'SystemTime 0x0E06', value: data.internalDate.toISOString() });
        }

        let messageData;
        try {
            messageData = await this.request(`/${this.oauth2UserPath}/mailFolders/${targetFolder.id}/messages`, 'post', messageUploadObj);
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

        let response = {
            message: messageData?.id,
            path: targetFolder.pathName,
            messageId: messageData?.internetMessageId || messageId
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

        let accountData = await this.accountObject.loadAccountData();
        if (!accountData.smtp && !accountData.oauth2 && !data.gateway) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        let { raw, messageId, queueId, job: jobData } = data;

        if (raw?.buffer) {
            // convert from a Uint8Array to a Buffer
            raw = Buffer.from(raw);
        }

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

        if (gatewayData) {
            // Send via SMTP
            return await super.submitMessage(data);
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
            await this.request(`/${this.oauth2UserPath}/sendMail`, 'post', Buffer.from(raw.toString('base64')), {
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
            reqUrl = `/${this.oauth2UserPath}/mailFolders/${parentFolder.id}/childFolders`;
        } else {
            // root folder
            reqUrl = `/${this.oauth2UserPath}/mailFolders`;
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
                .concat(parentFolder?.pathName || [])
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
                mailbox = await this.request(`/${this.oauth2UserPath}/mailFolders/${sourceFolder.id}`, 'patch', {
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
                mailbox = await this.request(`/${this.oauth2UserPath}/mailFolders/${sourceFolder.id}/move`, 'post', {
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
            await this.request(`/${this.oauth2UserPath}/mailFolders/${folder.id}`, 'delete', Buffer.alloc(0), { returnText: true });
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

    async externalNotify() {
        this.triggerSync();

        return true;
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

    async prepareDelegatedAccount() {
        if (this.delegatedAcountObject) {
            return;
        }

        let accountData = await this.accountObject.loadAccountData();
        if (accountData?.oauth2?.auth?.delegatedUser && accountData?.oauth2?.auth?.delegatedAccount) {
            await this.getDelegatedAccount(accountData);
            if (this.delegatedAcountObject) {
                this.oauth2UserPath = `users/${encodeURIComponent(accountData?.oauth2?.auth?.delegatedUser)}`;
            }
        }
    }

    async getToken() {
        const tokenData = await (this.delegatedAcountObject || this.accountObject).getActiveAccessTokenData();
        return tokenData.accessToken;
    }

    async getClient(force) {
        if (this.oAuth2Client && !force) {
            return this.oAuth2Client;
        }
        let accountData = await (this.delegatedAcountObject || this.accountObject).loadAccountData();
        this.oAuth2Client = await oauth2Apps.getClient(accountData.oauth2.provider, {
            logger: this.logger,
            logRaw: this.options.logRaw
        });
        return this.oAuth2Client;
    }

    async prepare() {
        await this.getAccount();
        await this.prepareDelegatedAccount();
        await this.getClient();
    }

    setupRenewWatchTimer() {
        if (this.closed) {
            return;
        }
        clearTimeout(this.renewWatchTimer);
        this.renewWatchTimer = setTimeout(() => {
            if (this.closed) {
                return;
            }
            this.ensureSubscription()
                .catch(err => {
                    this.logger.error({ msg: 'Failed to renew MS Graph change subscription', account: this.account, err });
                })
                .finally(() => {
                    // restart timer
                    this.setupRenewWatchTimer();
                });
        }, RENEW_WATCH_TTL);
        this.renewWatchTimer.unref();
    }

    // This is needed to check if there has been any changes in mailbox folder structure.
    // If a mailbox folder is added or removed, then the delta will change, so we should not use
    // cached mailbox listing and instead, generate a new listing
    async renewMailboxFolderCache() {
        // cache last known mailbox change
        let deltaReqUrl = (await this.redis.hget(this.getAccountKey(), 'outlookMailFoldersDeltaUrl')) || `/${this.oauth2UserPath}/mailFolders/delta`;

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

            let reqUrl = `/${this.oauth2UserPath}/mailFolders/${specialUseKey}`;
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
            let reqUrl = `/${this.oauth2UserPath}/mailFolders${folderId ? `/${folderId}/childFolders` : ''}`;
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

        path = [].concat(path || []).join('/');

        console.log('RESOLVING FOLDER', { path, options });

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
                pathParts[0] = inboxFolder.pathName;
            }
        }
        path = pathParts.join('/');

        if (options.pathNameOnly) {
            return { pathName: path };
        }

        let folderEntry = mailboxListing.find(entry => entry.pathName === path);

        return folderEntry;
    }

    async ensureSubscription() {
        let serviceUrl = (await settings.get('serviceUrl')) || null;
        if (!serviceUrl) {
            this.logger.fatal({ msg: 'Service URL not set' });
            return false;
        }

        let outlookSubscription = await this.redis.hget(this.getAccountKey(), 'outlookSubscription');
        if (outlookSubscription) {
            try {
                outlookSubscription = JSON.parse(outlookSubscription);
            } catch (err) {
                // ignore, I guess?
            }
        }

        if (!outlookSubscription) {
            outlookSubscription = {};
        }

        if (['creating', 'renewing'].includes(outlookSubscription.state?.state) && outlookSubscription.state.time > Date.now() - 30 * 60 * 1000) {
            // allow previous operation to finish
            return;
        }

        let now = Date.now();
        let expirationDateTime = new Date(now + OUTLOOK_EXPIRATION_TIME);

        if (outlookSubscription.id) {
            let existingExpirationDateTime = new Date(outlookSubscription.expirationDateTime);
            if (existingExpirationDateTime.toString() === 'Invalid Date') {
                existingExpirationDateTime = null;
            }

            if (existingExpirationDateTime && existingExpirationDateTime.getTime() < now) {
                //  already expired
                outlookSubscription = {};
            } else if (existingExpirationDateTime && existingExpirationDateTime.getTime() < now + OUTLOOK_EXPIRATION_RENEW_TIME) {
                outlookSubscription.state = {
                    state: 'renewing',
                    time: Date.now()
                };
                await this.redis.hSetExists(this.getAccountKey(), 'outlookSubscription', JSON.stringify(outlookSubscription));

                const subscriptionPayload = {
                    expirationDateTime: expirationDateTime.toISOString()
                };

                let subscriptionRes;
                try {
                    subscriptionRes = await this.request(`/subscriptions/${outlookSubscription?.id}`, 'patch', subscriptionPayload);
                    if (subscriptionRes?.expirationDateTime) {
                        outlookSubscription.expirationDateTime = subscriptionRes?.expirationDateTime;
                    }
                    outlookSubscription.state = {
                        state: 'created',
                        time: Date.now()
                    };
                } catch (err) {
                    outlookSubscription.state = {
                        state: 'error',
                        error: `Renewal failed: ${err.oauthRequest?.response?.error?.message || err.message}`,
                        time: Date.now()
                    };
                } finally {
                    await this.redis.hSetExists(this.getAccountKey(), 'outlookSubscription', JSON.stringify(outlookSubscription));
                }
            } else {
                // Subscription is valid, do nothing
                return;
            }
        }

        if (!outlookSubscription.id) {
            let queryArgs = `account=${encodeURIComponent(this.account)}`;

            const subscriptionPayload = {
                changeType: 'created,updated,deleted',
                notificationUrl: `${serviceUrl}/oauth/msg/notification?${queryArgs}`,
                lifecycleNotificationUrl: `${serviceUrl}/oauth/msg/lifecycle?${queryArgs}`,
                resource: `/${this.oauth2UserPath}/messages`,
                expirationDateTime: expirationDateTime.toISOString(),
                clientState: crypto.randomUUID()
            };

            outlookSubscription.state = {
                state: 'creating',
                time: Date.now()
            };
            await this.redis.hSetExists(this.getAccountKey(), 'outlookSubscription', JSON.stringify(outlookSubscription));

            let subscriptionRes;
            try {
                subscriptionRes = await this.request(`/subscriptions`, 'post', subscriptionPayload);
                if (subscriptionRes?.expirationDateTime) {
                    outlookSubscription = {
                        id: subscriptionRes.id,
                        expirationDateTime: subscriptionRes.expirationDateTime,
                        clientState: subscriptionRes.clientState,
                        state: {
                            state: 'created',
                            time: Date.now()
                        }
                    };
                } else {
                    throw new Error('Empty server response');
                }
            } catch (err) {
                outlookSubscription.state = {
                    state: 'error',
                    error: `Subscription failed: ${err.oauthRequest?.response?.error?.message || err.message}`,
                    time: Date.now()
                };
            } finally {
                await this.redis.hSetExists(this.getAccountKey(), 'outlookSubscription', JSON.stringify(outlookSubscription));
            }
        }
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

            headers: (extended && messageData.headers) || undefined,

            text: {
                id: messageData.id,
                encodedSize: encodedTextSize,
                plain: textContents?.plain?.toString(),
                html: textContents?.html?.toString(),
                hasMore: textContents?.plain || textContents?.html ? false : undefined
            },

            preview: messageData.bodyPreview
        };

        if (message.headers && this.isAutoreply(message)) {
            message.isAutoReply = true;
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

    async getAttachmentContent(attachmentId, options) {
        options = options || {};

        const [emailId, id] = msgpack.decode(Buffer.from(attachmentId, 'base64url'));

        await this.prepare();

        let attachmentResponse;

        try {
            attachmentResponse = await this.request(`/${this.oauth2UserPath}/messages/${emailId}/attachments/${id}`);
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
                        emailId,
                        err
                    });
                    throw err;
            }
        }

        const content = attachmentResponse?.contentBytes
            ? options.returnBase64
                ? attachmentResponse.contentBytes
                : Buffer.from(attachmentResponse.contentBytes, 'base64')
            : null;

        return options.contentOnly
            ? content
            : {
                  content,
                  contentType: attachmentResponse?.contentType,
                  filename: attachmentResponse?.name
              };
    }

    triggerSync() {
        if (this.processingHistory) {
            return;
        }
        this.processingHistory = true;
        this.processHistory()
            .catch(err => {
                this.logger.error({ msg: 'Failed to process account history', account: this.account, err });
            })
            .finally(() => {
                this.processingHistory = false;
            });
    }

    async processHistory() {
        let event;
        let newMessageOptions;

        while ((event = await this.accountObject.pullQueueEvent()) !== null) {
            switch (event.type) {
                case 'updated':
                    await this.processUpdatedMessage(event.message);
                    break;

                case 'deleted': {
                    await this.processDeletedMessage(event.message);
                    break;
                }

                case 'created': {
                    if (!newMessageOptions) {
                        // cache options
                        newMessageOptions = await this.getMessageFetchOptions();
                    }

                    newMessageOptions.showPath = true;

                    let messageData = await this.prepareNewMessage(event.message, newMessageOptions);
                    if (messageData) {
                        // When an email is sent, multiple "created" events are triggered: one for the draft and one for the sent mail folder.
                        // However, since we process the event with a delay, we only observe the message stored in the Sent Mail folder.
                        // This happens because the message was already moved there by the time we began processing the initial event from the drafts folder.

                        // Check rolling bucket lock to see if we recently processed the same new email event for the same folder
                        let recentlySeen = await this.rollingBucketLock(`${messageData.id}:created`, messageData.path);
                        if (recentlySeen) {
                            this.logger.debug({ msg: 'Ignore recently seen new email event', type: 'history-event', emailId: event.message });
                            break;
                        }

                        await this.processNew(messageData, newMessageOptions);
                    }
                    break;
                }

                default:
                    this.logger.debug({ msg: 'Future feature', type: 'history-event', event });
                    break;
            }
        }
    }

    async processDeletedMessage(emailId) {
        // Verify if the message was actually deleted.
        // If the email was moved, we receive both a 'deleted' and a 'created' event with the same ID.
        let messageData;
        try {
            messageData = await this.request(`/${this.oauth2UserPath}/messages/${emailId}`, 'get', {
                $select: ['id', 'parentFolderId'].join(',')
            });
        } catch (err) {
            this.logger.error({
                msg: 'Failed to fetch message data',
                emailId,
                err
            });
        }
        if (messageData) {
            // The message still exists, so there's no need to notify about the deletion.
            // The message was likely moved, but since we cannot determine the previous mailbox folder,
            // there is no point in notifying about it.
            this.logger.debug({ msg: 'Ignore deleted email event. Still exists.', type: 'history-event', emailId });
            return;
        }

        let messageUpdate = {
            id: emailId
        };

        await this.notify(this, MESSAGE_DELETED_NOTIFY, messageUpdate);
    }

    // We get too many "updated" events
    async processUpdatedMessage(emailId) {
        let messageData;

        try {
            messageData = await this.request(`/${this.oauth2UserPath}/messages/${emailId}`, 'get', {
                $select: ['id', 'isRead', 'isDraft', 'flag', 'conversationId', 'parentFolderId'].join(',')
            });
        } catch (err) {
            this.logger.error({
                msg: 'Failed to fetch message data',
                emailId,
                err
            });
        }
        if (!messageData) {
            // do nothing, message not found
            return;
        }

        let folder;
        try {
            folder = await this.resolveFolder(messageData.parentFolderId, { byId: true });
        } catch (err) {
            this.logger.error({
                msg: 'Failed to resolve folder for message',
                emailId,
                err
            });
        }

        let path = folder ? folder.pathName : this.path;
        let specialUse = folder ? folder.specialUse : this.listingEntry.specialUse;

        // we do not know which flags were added or removed, so list the full value

        const changes = { flags: { value: [] } };

        if (messageData.isRead) {
            changes.flags.value.push('\\Seen');
        }

        if (messageData.isDraft) {
            changes.flags.value.push('\\Draft');
        }

        if (messageData.flag?.flagStatus === 'flagged') {
            changes.flags.value.push('\\Flagged');
        }

        let messageUpdate = {
            id: messageData.id,
            threadId: messageData.conversationId,
            changes
        };

        // Check rolling bucket lock to see if we recently processed the update event for the same email
        let recentlySeen = await this.rollingBucketLock(`${messageData.id}:updated`, JSON.stringify(changes.flags.value));
        if (recentlySeen) {
            this.logger.debug({ msg: 'Ignore recently seen updated email event', type: 'history-event', emailId: messageData.id, flags: changes.flags.value });
            return;
        }

        await this.notify({ path, specialUse }, MESSAGE_UPDATED_NOTIFY, messageUpdate);
    }

    async prepareNewMessage(emailId, options) {
        this.logger.debug({ msg: 'New message', id: emailId, options });

        if (options.fetchHeaders) {
            options.headers = options.fetchHeaders;
        } else {
            options.headers = 'headers' in options ? options.headers : false;
        }

        let messageData = await this.getMessage(emailId, options);

        if (!messageData) {
            await this.notify(this, MESSAGE_MISSING_NOTIFY, {
                id: emailId
            });
            return;
        }

        // check if we have seen this message before or not (approximate estimation, not 100% exact)
        messageData.seemsLikeNew = messageData.messageSpecialUse !== '\\Sent' && !!(await this.redis.pfadd(this.getSeenMessagesKey(), messageData.messageId));

        return messageData;
    }

    async searchEmailIds(path, search) {
        let messages = [];
        let cursor;

        let maxMessages = 1000;
        let notDone = true;

        while (notDone) {
            let messageListResult = await this.listMessages(
                {
                    path,
                    pageSize: 250,
                    search,
                    cursor
                },
                { metadataOnly: true }
            );

            if (messageListResult?.messages) {
                messages = messages.concat(messageListResult?.messages);
                if (messages.length >= maxMessages) {
                    messages = messages.slice(0, maxMessages);
                    notDone = false;
                    break;
                }
            }

            if (!messageListResult.nextPageCursor) {
                notDone = false;
                break;
            }
            cursor = messageListResult.nextPageCursor;
        }

        return messages.map(message => message.id);
    }

    // convert IMAP SEARCH query object to a $search query
    prepareSearchQuery(search) {
        search = search || {};

        const searchParts = [];

        const enabledKeys = ['to', 'cc', 'bcc', 'larger', 'smaller', 'body', 'before', 'sentBefore', 'since', 'sentSince'];

        // not supported search terms
        for (let key of Object.keys(search)) {
            if (!enabledKeys.includes(key)) {
                let error = new Error(`Unsupported search term "${key}" for Outlook Search`);
                error.code = 'UnsupportedSearchTerm';
                error.statusCode = 400;
                throw error;
            }
        }

        let escapeString = term => {
            if (typeof term === 'object' && term && Object.prototype.toString.apply(new Date()) === '[object Date]') {
                // convert dates to "MM/DD/YYYY"
                let d = term.getDate();
                let m = term.getMonth() + 1;
                let y = term.getFullYear();
                term = `${m < 10 ? '0' : ''}${m}/${d < 10 ? '0' : ''}${d}/${y}`;
            }

            let str = term.replace(/[\s"']+/g, ' ').trim();
            if (str.indexOf(' ') >= 0) {
                str = `'${str}'`;
            }

            return str;
        };

        for (let key of ['from', 'to', 'cc', 'bcc', 'subject', 'body']) {
            if (search[key]) {
                searchParts.push(`${key}:${escapeString(search[key])}`);
            }
        }

        if (search.before || search.sentBefore) {
            searchParts.push(`received<=${escapeString(search.before || search.sentBefore)}`);
        }

        if (search.since || search.sentSince) {
            searchParts.push(`sent>=${escapeString(search.before || search.sentBefore)}`);
        }

        if (search.smaller) {
            searchParts.push(`size<${Number(search.smaller) || 0}`);
        }

        if (search.larger) {
            searchParts.push(`size>${Number(search.larger) || 0}`);
        }

        return searchParts.join(' ');
    }

    // convert IMAP SEARCH query object to a $filter query
    prepareFilterQuery(search) {
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

        return filterParts.join(' and ').trim();
    }

    async rollingBucketLock(key, value = '1') {
        // 10 minute buckets
        let currentBucketTime = new Date(`${new Date().toISOString().substring(0, 15)}0:00.000Z`).getTime();

        let buckets = 2;

        let pipeline = this.redis.multi();
        // Check one bucket to the future, current bucket, and one to the past
        // Always check newer first. In this case, if there is an outdated value in an older bucket, then we use the newer value
        for (let i = -1; i < buckets; i++) {
            let bucketTime = new Date(currentBucketTime - i * 10 * 60 * 1000).toISOString();
            let bucketKey = `${REDIS_PREFIX}bck:${bucketTime}`;
            pipeline = pipeline.hget(bucketKey, key);
        }

        let pipelineRes = await pipeline.exec();
        for (let [, bucketRes] of pipelineRes) {
            if (bucketRes) {
                if (bucketRes === value) {
                    return true;
                }
                // There is a value, but it does not match the known last value
                break;
            }
        }

        // Add the key to current bucket
        let bucketTime = new Date(currentBucketTime).toISOString();
        let bucketKey = `${REDIS_PREFIX}bck:${bucketTime}`;
        await this.redis
            .multi()
            .hset(bucketKey, key, value)
            // make sure the bucket does not expire until the next one is already valid
            .expire(bucketKey, 12 * 60)
            .exec();

        return false;
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
                let { page: cursorPage, skipToken } = JSON.parse(Buffer.from(cursorStr, 'base64url'));
                if (typeof cursorPage === 'number' && cursorPage >= 0) {
                    return { cursorPage, skipToken };
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

    encodeCursorString(cursorPage, skipToken) {
        if ((typeof cursorPage !== 'number' && !skipToken) || cursorPage < 0) {
            return null;
        }

        cursorPage = cursorPage || 0;

        let type = 'ms';
        let encodedToken = `${type}_${Buffer.from(JSON.stringify({ page: cursorPage, skipToken })).toString('base64url')}`;

        return encodedToken;
    }
}

module.exports = { OutlookClient };
