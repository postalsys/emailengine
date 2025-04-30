'use strict';

const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const msgpack = require('msgpack5')();
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');
const he = require('he');
const { BaseClient } = require('./base-client');
const { mimeHtml } = require('@postalsys/email-text-tools');
const { emitChangeEvent } = require('../tools');
const { Gateway } = require('../gateway');

const {
    MESSAGE_UPDATED_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_MISSING_NOTIFY,
    EMAIL_SENT_NOTIFY,
    REDIS_PREFIX,
    AUTH_ERROR_NOTIFY,
    AUTH_SUCCESS_NOTIFY
} = require('../consts');

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

const SYSTEM_LABELS_REV = {};
for (let label of Object.keys(SYSTEM_LABELS)) {
    SYSTEM_LABELS_REV[SYSTEM_LABELS[label]] = label;
}

const RENEW_WATCH_TTL = 60 * 60 * 1000; // 1h
const MIN_WATCH_TTL = 24 * 3600 * 1000; // 1day

/*

✅ listMessages
  ✅ paging - cursor based
✅ getText
✅ getMessage
✅ updateMessage
✅ updateMessages
✅ listMailboxes
✅ moveMessage
✅ moveMessages
✅ deleteMessage - no force option
✅ deleteMessages - no force option
✅ getRawMessage
🟡 getQuota - not supported
✅ createMailbox
✅ renameMailbox
✅ deleteMailbox
✅ getAttachment
✅ submitMessage
✅ uploadMessage
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
                    error.statusCode = 400;
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
        if (this.cursorList.length < 1) {
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

        this.cachedAccessToken = null;
        this.cachedAccessTokenRaw = null;

        // pseudo path for webhooks
        this.path = '\\All';
        this.listingEntry = { specialUse: '\\All' };

        this.processingHistory = null;
        this.renewWatchTimer = null;

        this.cachedLabels = null;
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
            result = await this.oAuth2Client.request(accessToken, ...args);
        } catch (err) {
            this.logger.error({ msg: 'Failed to run API request', account: this.account, err });
            throw err;
        }

        return result;
    }

    // PUBLIC METHODS

    async init(opts) {
        opts = opts || {};

        await this.getAccount();
        await this.getClient(true);

        let accountData = await this.accountObject.loadAccountData(this.account, false);

        await this.renewWatch(accountData, opts);

        let profileRes;
        try {
            profileRes = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/profile`);
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

        if (profileRes.emailAddress && accountData.oauth2.auth?.user !== profileRes.emailAddress) {
            updates.oauth2 = {
                partial: true,
                auth: Object.assign(accountData.oauth2.auth || {}, {
                    // update username
                    user: profileRes.emailAddress
                })
            };
        }

        if (!accountData.locale) {
            try {
                let locale = await this.getLocale();
                if (locale) {
                    updates.locale = locale;
                }
            } catch (err) {
                // not very important if succeeds or not
                this.logger.error({
                    msg: 'Failed to resolve locale for account',
                    err
                });
            }
        }

        if (Object.keys(updates).length) {
            await this.accountObject.update(updates);
            accountData = await this.accountObject.loadAccountData(this.account, false);
        }

        this.logger.info({
            msg: 'Initializing Gmail account',
            provider: accountData.oauth2.provider,
            user: accountData.oauth2.auth?.user
        });

        if (
            accountData.oauth2.auth?.user &&
            (await this.redis.hget(`${REDIS_PREFIX}oapp:h:${accountData.oauth2.provider}`, accountData.oauth2.auth?.user)) !== this.account
        ) {
            await this.redis.hset(`${REDIS_PREFIX}oapp:h:${accountData.oauth2.provider}`, accountData.oauth2.auth?.user, this.account);
            this.logger.info({ msg: 'Re-set missing Google Pub/Sub subscription', account: this.account, emailAddress: accountData.oauth2.auth?.user });
        }

        let historyId = Number(profileRes?.historyId) || null;
        if (!accountData.googleHistoryId) {
            // set as initial
            await this.redis.hset(this.getAccountKey(), 'googleHistoryId', historyId.toString());
            accountData.googleHistoryId = historyId;
            this.logger.info({ msg: 'Re-set missing Google History ID', account: this.account, historyId });
        }

        if (historyId && accountData.googleHistoryId && historyId > accountData.googleHistoryId) {
            // changes detected
            this.triggerSync(accountData.googleHistoryId, historyId);
        }

        this.setupRenewWatchTimer();

        let prevConnectedCount = await this.redis.hget(this.getAccountKey(), `state:count:connected`);
        let isFirstSuccessfulConnection = prevConnectedCount === '0'; // string zero means the account has been initialized but not yet connected

        this.state = 'connected';
        await this.setStateVal();

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
        return await this.init({ forceWatchRenewal: true });
    }

    // TODO: check for changes (added, deleted folders)
    async listMailboxes(options) {
        await this.prepare();

        let labelsResult = await this.getLabels();

        let labels = labelsResult.filter(label => !SKIP_LABELS.includes(label.id));

        let resultLabels;
        if (options && options.statusQuery?.unseen) {
            let promises = [];
            resultLabels = [];

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
                        resultLabels.push(entry.value);
                    }
                }
                promises = [];
            };

            for (let label of labels) {
                promises.push(this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/labels/${label.id}`));
                if (promises.length > LIST_BATCH_SIZE) {
                    await resolvePromises();
                }
            }
            await resolvePromises();
        } else {
            resultLabels = labels;
        }

        let mailboxes = resultLabels
            .map(label => {
                let pathParts = label.name.split('/');
                let name = pathParts.pop();
                let parentPath = pathParts.join('/');

                let folderData = {
                    id: label.id,
                    path: label.name,
                    delimiter: '/',
                    parentPath,
                    name: label.type === 'system' && SYSTEM_NAMES[name] ? SYSTEM_NAMES[name] : name,
                    listed: true,
                    subscribed: true
                };

                if (label.type === 'system' && SYSTEM_LABELS.hasOwnProperty(label.id)) {
                    folderData.specialUse = SYSTEM_LABELS[label.id];
                    folderData.specialUseSource = 'extension';
                }

                if (label.type === 'system' && /^CATEGORY/.test(label.id)) {
                    return false;
                }

                if (!isNaN(label.messagesTotal) && options?.statusQuery?.messages) {
                    folderData.status = {
                        messages: Number(label.messagesTotal) || 0,
                        unseen: Number(label.messagesUnread) || 0
                    };
                }

                return folderData;
            })
            .filter(value => value)
            .sort((a, b) => {
                if (a.path === 'INBOX') {
                    return -1;
                } else if (b.path === 'INBOX') {
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

        let page = Number(query.page) || 0;
        if (page > 0) {
            let error = new Error('Invalid page number. Only paging cursors are allowed for Gmail accounts.');
            error.code = 'InvalidInput';
            error.statusCode = 400;
            throw error;
        }

        let pageSize = Math.abs(Number(query.pageSize) || 20);
        let requestQuery = {
            maxResults: pageSize
        };

        let pageCursor = PageCursor.create(query.cursor);

        let path;
        if (query.path && query.path !== '\\All') {
            let label = await this.getLabel(query.path);
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
                let threadListingResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/threads/${query.search.threadId}`, 'get', {
                    format: 'full'
                });

                let messageCount = threadListingResult?.messages?.length || 0;
                let currentPage = pageCursor.currentPage();

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

        let listingResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages`, 'get', requestQuery);
        let messageCount = listingResult.resultSizeEstimate;

        let pages = Math.ceil(messageCount / pageSize);

        let nextPageCursor = pageCursor.nextPageCursor(listingResult.nextPageToken);
        let prevPageCursor = pageCursor.prevPageCursor();

        if (options.metadataOnly) {
            return {
                total: messageCount,
                page: currentPage.page,
                pages,
                nextPageCursor,
                prevPageCursor,
                messages: listingResult.messages
            };
        }

        // Fetch message content for matching messages

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

        for (let { id: message } of listingResult.messages || []) {
            promises.push(this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${message}`));
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

    async getRawMessage(emailId) {
        await this.prepare();

        const requestQuery = {
            format: 'raw'
        };
        const result = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}`, 'get', requestQuery);

        return result?.raw ? Buffer.from(result?.raw, 'base64url') : null;
    }

    async deleteMessage(emailId /*, force*/) {
        await this.prepare();

        // Move to trash
        const url = `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}/trash`;
        const result = await this.request(url, 'post', Buffer.alloc(0));

        return {
            deleted: result && result.labelIds?.includes('TRASH'),
            moved: {
                message: result.id
            }
        };
    }

    async deleteMessages(path, search) {
        await this.prepare();

        path = [].concat(path || []).join('/');

        let sourceLabel = path && path !== '\\All' ? await this.getLabel(path) : null;
        if (path && path !== '\\All' && !sourceLabel) {
            let error = new Error('Unknown path');
            error.info = {
                response: `Mailbox doesn't exist: ${path}`
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }

        let labelsUpdate = { add: 'TRASH' };
        if (sourceLabel) {
            labelsUpdate.delete = sourceLabel.id;
        }

        let updateResult = await this.updateMessages(path, search, { labels: labelsUpdate });

        return {
            deleted: true,
            moved: {
                destination: SYSTEM_NAMES.TRASH,
                emailIds: updateResult.emailIds
            }
        };
    }

    async updateMessage(emailId, updates) {
        await this.prepare();
        updates = updates || {};

        let addLabelIds = new Set();
        let removeLabelIds = new Set();

        if (updates.flags) {
            let labelUpdates = [];

            for (let flag of [].concat(updates.flags.add || [])) {
                labelUpdates.push(this.flagToLabel(flag));
            }

            for (let flag of [].concat(updates.flags.delete || [])) {
                labelUpdates.push(this.flagToLabel(flag, true));
            }

            labelUpdates
                .filter(label => label)
                .forEach(label => {
                    if (label.add) {
                        addLabelIds.add(label.add);
                    }
                    if (label.remove) {
                        removeLabelIds.add(label.remove);
                    }
                });
        }

        if (updates.labels) {
            for (let label of [].concat(updates.labels.add || [])) {
                if (SYSTEM_LABELS_REV.hasOwnProperty(label)) {
                    label = SYSTEM_LABELS_REV[label];
                }
                addLabelIds.add(label);
            }

            for (let label of [].concat(updates.labels.delete || [])) {
                if (SYSTEM_LABELS_REV.hasOwnProperty(label)) {
                    label = SYSTEM_LABELS_REV[label];
                }
                removeLabelIds.add(label);
            }
        }

        if (!addLabelIds.size && !removeLabelIds.size) {
            return updates;
        }

        let labelUpdates = {};

        if (addLabelIds.size) {
            labelUpdates.addLabelIds = Array.from(addLabelIds);
        }

        if (removeLabelIds.size) {
            labelUpdates.removeLabelIds = Array.from(removeLabelIds);
        }

        let modifyResult;

        try {
            modifyResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}/modify`, 'post', labelUpdates);
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 400: {
                    // invalid name
                    let error = new Error(err?.oauthRequest?.response?.error?.message || 'Invalid label');
                    error.info = {
                        response: err?.oauthRequest?.response?.error?.message
                    };
                    error.code = err?.oauthRequest?.response?.error?.status;
                    error.statusCode = 400;
                    throw error;
                }

                case 403: {
                    // invalid name
                    let error = new Error(err?.oauthRequest?.response?.error?.message || 'Permission Denied');
                    error.info = {
                        response: err?.oauthRequest?.response?.error?.message
                    };
                    error.code = err?.oauthRequest?.response?.error?.status;
                    error.statusCode = 403;
                    throw error;
                }
            }

            throw err;
        }

        let { flags: messageFlags, labels: messageLabels } = this.formatFlagsAndLabels(modifyResult);

        let response = {
            flags: Object.assign({}, updates.flags || {}, { result: messageFlags || [] }),
            labels: Object.assign({}, updates.labels || {}, { result: messageLabels || [] })
        };

        return response;
    }

    async updateMessages(path, search, updates) {
        await this.prepare();
        updates = updates || {};

        // Step 1. Resolve matching messages
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

        let emailIds = messages.map(message => message.id);

        if (!emailIds?.length) {
            // nothing to do here
            return updates;
        }

        let addLabelIds = new Set();
        let removeLabelIds = new Set();

        if (updates.flags) {
            let labelUpdates = [];

            for (let flag of [].concat(updates.flags.add || [])) {
                labelUpdates.push(this.flagToLabel(flag));
            }

            for (let flag of [].concat(updates.flags.delete || [])) {
                labelUpdates.push(this.flagToLabel(flag), true);
            }

            labelUpdates
                .filter(label => label)
                .forEach(label => {
                    if (label.add) {
                        addLabelIds.add(label.add);
                    }
                    if (label.remove) {
                        removeLabelIds.add(label.remove);
                    }
                });
        }

        if (updates.labels) {
            for (let label of [].concat(updates.labels.add || [])) {
                addLabelIds.add(label);
            }

            for (let label of [].concat(updates.labels.delete || [])) {
                removeLabelIds.add(label);
            }
        }

        if (!addLabelIds.size && !removeLabelIds.size) {
            return { flags: {}, labels: {} };
        }

        let labelUpdates = {
            ids: emailIds
        };

        if (addLabelIds.size) {
            labelUpdates.addLabelIds = Array.from(addLabelIds);
        }

        if (removeLabelIds.size) {
            labelUpdates.removeLabelIds = Array.from(removeLabelIds);
        }

        await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/batchModify`, 'post', labelUpdates, { returnText: true });

        return Object.assign({}, updates, {
            emailIds
        });
    }

    async moveMessage(emailId, target, options) {
        await this.prepare();

        options = options || {};

        let path = [].concat(target?.path || []).join('/');

        let label = await this.getLabel(path);
        if (!label) {
            let error = new Error('Unknown path');
            error.info = {
                response: `Mailbox doesn't exist: ${path}`
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }
        let labelsUpdate = { add: [label.id] };

        let sourcePath = options.source?.path;

        let sourceLabel = sourcePath ? await this.getLabel(sourcePath) : null;
        if (sourcePath && !sourceLabel) {
            let error = new Error('Unknown path');
            error.info = {
                response: `Mailbox doesn't exist: ${sourcePath}`
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }

        if (sourceLabel) {
            labelsUpdate.delete = sourceLabel.id;
        }

        await this.updateMessage(emailId, { labels: labelsUpdate });

        return {
            path,
            id: emailId
        };
    }

    async moveMessages(source, search, target) {
        await this.prepare();

        let path = [].concat(target?.path || []).join('/');

        let targetLabel = await this.getLabel(path);
        if (!targetLabel) {
            let error = new Error('Unknown path');
            error.info = {
                response: `Mailbox doesn't exist: ${path}`
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }

        let sourceLabel = source ? await this.getLabel(source) : null;
        if (source && !sourceLabel) {
            let error = new Error('Unknown path');
            error.info = {
                response: `Mailbox doesn't exist: ${source}`
            };
            error.code = 'NotFound';
            error.statusCode = 404;
            throw error;
        }

        let labelsUpdate = { add: targetLabel.id };
        if (sourceLabel) {
            labelsUpdate.delete = sourceLabel.id;
        }

        let updateResult = await this.updateMessages(source, search, { labels: labelsUpdate });

        return {
            path,
            emailIds: updateResult?.emailIds || null
        };
    }

    async getAttachment(attachmentId) {
        let attachmentData = await this.getAttachmentContent(attachmentId);

        if (!attachmentData || !attachmentData.content) {
            return false;
        }

        let filenameParam = '';
        if (attachmentData.filename) {
            let isCleartextFilename = attachmentData.filename && /^[a-z0-9 _\-()^[\]~=,+*$]+$/i.test(attachmentData.filename);
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
            disposition: attachmentData.disposition,
            data: attachmentData.content
        };

        return contentResponse;
    }

    async getMessage(emailId, options) {
        options = options || {};
        await this.prepare();

        if (options.webSafeHtml) {
            options.textType = '*';
            options.embedAttachedImages = true;
            options.preProcessHtml = true;
        }

        const requestQuery = {
            format: 'full'
        };
        const messageData = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}`, 'get', requestQuery);

        let formattedMessage = this.formatMessage(messageData, { extended: true, textType: options.textType });

        if (options.markAsSeen && (!formattedMessage.flags || !formattedMessage.flags.includes('\\Seen'))) {
            //
            try {
                let response = await this.updateMessage(emailId, { flags: { add: ['\\Seen'] } });
                if (response?.flags?.result) {
                    formattedMessage.flags = response?.flags?.result;
                }
            } catch (err) {
                this.logger.debug({ msg: 'Failed to mark message as Seen', message: emailId, err });
            }
        }

        if (options.preProcessHtml && formattedMessage.text && (formattedMessage.text.html || formattedMessage.text.plain)) {
            formattedMessage.text.html = mimeHtml({
                html: formattedMessage.text.html,
                text: formattedMessage.text.plain
            });
            formattedMessage.text.webSafe = true;
        }

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

        return formattedMessage;
    }

    async getText(textId, options) {
        options = options || {};
        await this.prepare();

        const [emailId, textParts] = msgpack.decode(Buffer.from(textId, 'base64url'));

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
        const messageData = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}`, 'get', requestQuery);

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

    async uploadMessage(data) {
        await this.prepare();

        let path = [].concat(data.path || []).join('/');

        let targetLabel = await this.getLabel(path);
        if (!targetLabel) {
            let error = new Error('Unknown path');
            error.info = {
                response: `Mailbox doesn't exist: ${path}`
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

        let payload = {
            labelIds: [targetLabel.id],
            raw: raw.toString('base64url')
        };

        if (referencedMessage?.threadId) {
            payload.threadId = referencedMessage.threadId;
        }

        let uploadInfo;
        try {
            uploadInfo = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages?internalDateSource=dateHeader`, 'post', payload);
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 403: {
                    // permission denied
                    let error = new Error(err?.oauthRequest?.response?.error?.message || 'Permission Denied');
                    error.info = {
                        response: err?.oauthRequest?.response?.error?.message
                    };
                    error.code = err?.oauthRequest?.response?.error?.status;
                    error.statusCode = 403;
                    throw error;
                }
            }

            throw err;
        }

        let response = {
            id: uploadInfo?.id,
            path: [].concat(data.path || []).join('/'),
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

        let contentType = 'message/rfc822';
        let payload = raw;
        let targetEndpoint = `/upload/gmail/v1/users/me/messages/send`;

        if (data?.reference?.threadId) {
            targetEndpoint = `/gmail/v1/users/me/messages/send`;
            contentType = 'application/json';
            payload = {
                raw: raw.toString('base64'),
                threadId: data?.reference?.threadId
            };
        }

        const submitInfo = await this.request(`${GMAIL_API_BASE}${targetEndpoint}`, 'post', payload, { contentType });
        /*
            SEND RESPONSE {
            id: '18f85d2eb6adb232',
            threadId: '18f85d2eb6adb232',
            labelIds: [ 'SENT' ]
            }
        */

        let gmailMessageId;
        if (submitInfo?.id) {
            // fetch message data to get actual Message-ID value
            let messageEntry = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${submitInfo?.id}`, 'get', {
                format: 'metadata',
                metadataHeaders: 'message-id'
            });
            let messageIdHeader = messageEntry?.payload?.headers?.find(h => /^Message-ID$/i.test(h.name));
            gmailMessageId = messageIdHeader?.value;
        }

        try {
            // try to update
            await submitJobEntry.updateProgress({
                status: 'smtp-completed',
                messageId: gmailMessageId,
                originalMessageId: messageId
            });
        } catch (err) {
            // ignore
        }

        await this.notify(false, EMAIL_SENT_NOTIFY, {
            messageId: gmailMessageId,
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
            messageId: gmailMessageId
        };
    }

    async createMailbox(path) {
        path = [].concat(path || []).join('/');

        await this.prepare();

        let labelData = {
            name: path
        };

        let label;
        try {
            label = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/labels`, 'post', labelData);

            // clear cache
            this.cachedLabels = null;
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 409:
                    // already exists
                    return {
                        path,
                        created: false
                    };

                case 400: {
                    // invalid name
                    let error = new Error('Create failed');
                    error.info = {
                        response: err?.oauthRequest?.response?.error?.message
                    };
                    error.code = err?.oauthRequest?.response?.error?.status;
                    error.statusCode = 400;
                    throw error;
                }
            }

            throw err;
        }

        return {
            mailboxId: label.id,
            path: label.name,
            created: true
        };
    }

    async renameMailbox(path, newPath) {
        path = [].concat(path || []).join('/');
        newPath = [].concat(newPath || []).join('/');

        await this.prepare();

        let existingLabel = await this.getLabel(path);
        if (!existingLabel || existingLabel.type !== 'user') {
            return {
                path,
                newPath,
                renamed: false
            };
        }

        let labelData = {
            name: newPath
        };

        let label;
        try {
            label = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/labels/${existingLabel.id}`, 'patch', labelData);

            // clear cache
            this.cachedLabels = null;
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 409:
                case 400: {
                    // invalid name
                    let error = new Error('Rename failed');
                    error.info = {
                        response: err?.oauthRequest?.response?.error?.message
                    };
                    error.code = err?.oauthRequest?.response?.error?.status;
                    error.statusCode = 400;
                    throw error;
                }
            }

            throw err;
        }

        return {
            mailboxId: existingLabel.id,
            path,
            newPath: label.name,
            renamed: true
        };
    }

    async deleteMailbox(path) {
        path = [].concat(path || []).join('/');

        await this.prepare();

        let existingLabel = await this.getLabel(path);
        if (!existingLabel || existingLabel.type !== 'user') {
            return {
                path,
                deleted: false
            };
        }

        try {
            await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/labels/${existingLabel.id}`, 'delete', Buffer.alloc(0), { returnText: true });

            // clear cache
            this.cachedLabels = null;
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                case 409:
                case 400: {
                    // invalid name
                    let error = new Error('Delete failed');
                    error.info = {
                        response: err?.oauthRequest?.response?.error?.message
                    };
                    error.code = err?.oauthRequest?.response?.error?.status;
                    error.statusCode = 400;
                    throw error;
                }
            }

            throw err;
        }

        return {
            mailboxId: existingLabel.id,
            path,
            deleted: true
        };
    }

    async externalNotify(message) {
        let { historyId } = message || {};

        let existingHistoryId = Number(await this.redis.hget(this.getAccountKey(), 'googleHistoryId')) || null;
        if (historyId && (!existingHistoryId || historyId > existingHistoryId)) {
            // changes detected
            this.triggerSync(existingHistoryId, historyId);
        }

        return true;
    }

    // PRIVATE METHODS

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
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

    setupRenewWatchTimer() {
        if (this.closed) {
            return;
        }
        clearTimeout(this.renewWatchTimer);
        this.renewWatchTimer = setTimeout(() => {
            if (this.closed) {
                return;
            }
            this.renewWatch()
                .catch(err => {
                    this.logger.error({ msg: 'Failed to renew Gmail subscription watch', account: this.account, err });
                })
                .finally(() => {
                    // restart timer
                    this.setupRenewWatchTimer();
                });
        }, RENEW_WATCH_TTL);
        this.renewWatchTimer.unref();
    }

    async renewWatch(accountData, opts) {
        let { forceWatchRenewal } = opts || {};

        if (!accountData) {
            await this.getAccount();
            accountData = await this.accountObject.loadAccountData(this.account, false);
        }

        let now = Date.now();

        if (accountData._app?.pubSubApp && (forceWatchRenewal || !accountData.lastWatch || accountData.lastWatch < new Date(now - MIN_WATCH_TTL))) {
            let appData = await oauth2Apps.get(accountData._app?.pubSubApp);
            if (appData?.pubSubTopic && appData.pubSubIamPolicy) {
                await this.prepare();
                try {
                    let watchResponse = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/watch`, 'post', {
                        topicName: appData?.pubSubTopic
                    });
                    // { historyId: '3663748', expiration: '1720183655953' }
                    await this.accountObject.update({
                        lastWatch: new Date(now),
                        watchResponse,
                        watchFailure: null
                    });
                    this.logger.info({
                        msg: 'Renewed Gmail pubsub watch',
                        account: this.account,
                        watchResponse
                    });
                } catch (err) {
                    await this.accountObject.update({
                        lastWatch: new Date(now),
                        watchFailure: {
                            err: err.message,
                            req: err.oauthRequest
                        }
                    });
                    this.logger.error({
                        msg: 'Failed to set up Gmail pubsub watch',
                        account: this.account,
                        err
                    });
                }
            }
        }
    }

    async getLabels(force) {
        let now = Date.now();
        if (this.cachedLabels && !force && now <= this.cachedLabelsTime + 3600 * 1000) {
            return this.cachedLabels;
        }

        try {
            let cachedLabels = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/labels`);
            this.cachedLabels = cachedLabels?.labels;
            this.cachedLabelsTime = now;

            return this.cachedLabels;
        } catch (err) {
            if (this.cachedLabels) {
                return this.cachedLabels;
            }
            throw err;
        }
    }

    async getLabel(path) {
        path = []
            .concat(path || '')
            .join('/')
            .replace(/^INBOX(\/|$)/gi, 'INBOX');

        for (let label of Object.keys(SYSTEM_LABELS)) {
            if (SYSTEM_LABELS[label].toLowerCase() === path.toLowerCase()) {
                path = label;
                break;
            }
        }

        for (let label of Object.keys(SYSTEM_NAMES)) {
            if (SYSTEM_NAMES[label].toLowerCase() === path.toLowerCase()) {
                path = label;
                break;
            }
        }

        let labelsResult = await this.getLabels();
        let label = labelsResult.find(entry => entry.name === path || entry.id === path);
        if (!label) {
            // try again by fetching the list without cache
            labelsResult = await this.getLabels(true);
            label = labelsResult.find(entry => entry.name === path || entry.id === path);
        }

        if (!label) {
            return false;
        }

        return label;
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
                    const attachmentIdProps = [
                        messageData.id,
                        node.mimeType || null,
                        disposition?.value || null,
                        node.filename || null,
                        node.body.attachmentId
                    ];

                    const attachment = {
                        // append body part nr to message id
                        id: msgpack.encode(attachmentIdProps).toString('base64url'),
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

    formatFlagsAndLabels(messageData) {
        messageData = messageData || {};

        let flags = [];
        let labels = [];
        let category;

        if (!messageData.labelIds?.includes('UNREAD')) {
            flags.push('\\Seen');
        }

        if (messageData.labelIds?.includes('STARRED')) {
            flags.push('\\Flagged');
        }

        if (messageData.labelIds?.includes('DRAFTS')) {
            flags.push('\\Draft');
        }

        for (let label of messageData.labelIds || []) {
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

        return { flags, labels, category };
    }

    formatMessage(messageData, options) {
        let { extended, path, textType } = options || {};

        let date = messageData.internalDate && !isNaN(messageData.internalDate) ? new Date(Number(messageData.internalDate)) : undefined;
        if (date?.toString() === 'Invalid Date') {
            date = undefined;
        }

        let { flags, labels, category } = this.formatFlagsAndLabels(messageData);

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

        let preview;
        try {
            preview = he.decode(messageData.snippet);
        } catch (err) {
            preview = messageData.snippet;
        }

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

            preview
        };

        if (this.isAutoreply(result)) {
            result.isAutoReply = true;
        }

        for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
            if (result.labels && result.labels.includes(specialUseTag)) {
                result.messageSpecialUse = specialUseTag;
                break;
            }
        }

        return result;
    }

    async getAttachmentContent(attachmentId, options) {
        options = options || {};
        const [emailId, contentType, disposition, filename, id] = msgpack.decode(Buffer.from(attachmentId, 'base64url'));

        await this.prepare();

        const requestQuery = {};
        const result = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}/attachments/${id}`, 'get', requestQuery);

        const content = result?.data ? Buffer.from(result?.data, 'base64url') : null;

        return options.contentOnly
            ? content
            : {
                  content,
                  contentType,
                  disposition,
                  filename
              };
    }

    formatSearchTerm(term, quot = '"') {
        if (typeof term === 'object' && term && Object.prototype.toString.apply(new Date()) === '[object Date]') {
            term = term.toISOString().substring(0, 10);
        }

        term = (term || '')
            .toString()
            .replace(/[\s"]+/g, ' ')
            .trim();

        if (term.indexOf(' ') >= 0) {
            return `${quot ? quot : ''}${term}${quot ? quot : ''}`;
        }
        return term;
    }

    flagToLabel(flag, remove) {
        switch (flag) {
            case '\\Seen':
                return { [remove ? 'add' : 'remove']: 'UNREAD' };
            case '\\Flagged':
                return { [remove ? 'remove' : 'add']: 'STARRED' };
        }
    }

    // convert IMAP SEARCH query object to a Gmail API search query
    prepareQuery(search) {
        search = search || {};

        const queryParts = [];

        // not supported search terms
        for (let disabledKey of ['seq', 'uid', 'paths', 'modseq', 'answered', 'deleted', 'draft']) {
            if (disabledKey in search) {
                let error = new Error(`Unsupported search term "${disabledKey}"`);
                error.code = 'UnsupportedSearchTerm';
                error.statusCode = 400;
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
            queryParts.push(`is:${search.seen ? 'read' : 'unread'}`);
        }

        for (let key of ['from', 'to', 'cc', 'bcc', 'subject']) {
            if (search[key]) {
                queryParts.push(`${key}:${this.formatSearchTerm(search[key])}`);
            }
        }

        for (let key of ['since', 'sentSince']) {
            if (search[key]) {
                queryParts.push(`after:${this.formatSearchTerm(search[key], false)}`);
            }
        }

        for (let key of ['before', 'sentBefore']) {
            if (search[key]) {
                queryParts.push(`before:${this.formatSearchTerm(search[key])}`);
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
                    error.statusCode = 400;
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

    triggerSync(currentHistoryId, updatedHistoryId) {
        if (this.processingHistory) {
            return;
        }
        this.processingHistory = true;
        this.processHistory(currentHistoryId, updatedHistoryId)
            .catch(err => {
                this.logger.error({ msg: 'Failed to process account history', currentHistoryId, updatedHistoryId, account: this.account, err });
            })
            .finally(() => {
                this.processingHistory = false;
            });
    }

    async processHistoryEntry(historyEntry) {
        let labels = await this.getLabels();

        let processLabels = async (labelsValue, direction) => {
            let addedProp, deletedProp;
            switch (direction) {
                case 'remove':
                    addedProp = 'deleted';
                    deletedProp = 'added';
                    break;
                case 'add':
                default:
                    addedProp = 'added';
                    deletedProp = 'deleted';
                    break;
            }

            for (let entry of labelsValue || []) {
                if (!entry?.message) {
                    continue;
                }

                let changes = { flags: { added: [], deleted: [] }, labels: { added: [], deleted: [] } };
                for (let labelId of entry?.labelIds || []) {
                    switch (labelId) {
                        case 'UNREAD':
                            changes.flags[deletedProp].push('\\Seen');
                            break;
                        case 'STARRED':
                            changes.flags[addedProp].push('\\Flagged');
                            break;
                        case 'DRAFTS':
                            changes.flags[addedProp].push('\\Draft');
                            break;
                        default:
                            if (SKIP_LABELS.includes(labelId)) {
                                continue;
                            }
                            if (SYSTEM_LABELS.hasOwnProperty(labelId)) {
                                changes.labels[addedProp].push(SYSTEM_LABELS[labelId]);
                            } else if (SYSTEM_NAMES.hasOwnProperty(labelId) && /^CATEGORY/.test(labelId)) {
                                // ignore category labels
                            } else {
                                // resolve Path for the label
                                let label = labels.find(label => label.id === labelId);
                                if (label) {
                                    changes.labels[addedProp].push(label.name);
                                }
                            }
                            break;
                    }
                }

                let { flags: messageFlags, labels: messageLabels } = this.formatFlagsAndLabels(entry?.message);

                // clear empty values
                for (let key of ['added', 'deleted']) {
                    if (!changes.flags[key]?.length) {
                        delete changes.flags[key];
                    }
                    if (!changes.labels[key]?.length) {
                        delete changes.labels[key];
                    }
                }

                if (!Object.keys(changes.flags).length) {
                    delete changes.flags;
                } else {
                    changes.flags.value = messageFlags;
                }

                if (!Object.keys(changes.labels).length) {
                    delete changes.labels;
                } else {
                    changes.labels.value = messageLabels;
                }

                let messageUpdate = {
                    id: entry.message.id,
                    threadId: entry.message.threadId,
                    changes
                };

                await this.notify(this, MESSAGE_UPDATED_NOTIFY, messageUpdate);
            }
        };

        await processLabels(historyEntry?.labelsAdded, 'add');
        await processLabels(historyEntry?.labelsRemoved, 'remove');

        for (let entry of historyEntry?.messagesDeleted || []) {
            // new email
            if (!entry?.message) {
                continue;
            }
            let { flags: messageFlags, labels: messageLabels, category: messageCategory } = this.formatFlagsAndLabels(entry?.message);
            let messageUpdate = {
                id: entry.message.id,
                threadId: entry.message.threadId,
                flags: messageFlags,
                labels: messageLabels,
                category: messageCategory
            };
            await this.notify(this, MESSAGE_DELETED_NOTIFY, messageUpdate);
        }

        const newMessageOptions = await this.getMessageFetchOptions();
        for (let entry of historyEntry?.messagesAdded || []) {
            // new email
            if (!entry?.message) {
                continue;
            }

            const { flags: messageFlags, labels: messageLabels, category: messageCategory } = this.formatFlagsAndLabels(entry?.message);
            const eventEntry = {
                id: entry.message.id,
                threadId: entry.message.threadId,
                flags: messageFlags,
                labels: messageLabels,
                category: messageCategory
            };

            const messageData = await this.prepareNewMessage(eventEntry, newMessageOptions);
            if (messageData) {
                await this.processNew(messageData, newMessageOptions);
            }
        }
    }

    async processHistory(currentHistoryId, updatedHistoryId) {
        let newestHistoryId = currentHistoryId;
        let lastHistoryId = currentHistoryId;

        let getHistoryPage = async pageToken => {
            let queryArgs = {
                startHistoryId: currentHistoryId,
                maxResults: 500
            };

            if (pageToken) {
                queryArgs.pageToken = pageToken;
            }

            let historyRes;
            try {
                historyRes = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/history`, 'get', queryArgs);
            } catch (err) {
                switch (err?.oauthRequest?.response?.error?.code) {
                    case 404: {
                        // does not exist
                        this.logger.info({ msg: 'Provided history ID is too old', account: this.account, historyId: currentHistoryId, updatedHistoryId, err });
                        // set to newest known value, ignore missed entries
                        newestHistoryId = updatedHistoryId;
                        return;
                    }
                    default:
                        throw err;
                }
            }

            for (let entry of historyRes?.history || []) {
                try {
                    await this.processHistoryEntry(entry);
                    let historyEntryId = Number(entry?.id) || null;
                    if (historyEntryId && historyEntryId > lastHistoryId) {
                        await this.redis.hset(this.getAccountKey(), 'googleHistoryId', historyEntryId.toString());
                        lastHistoryId = historyEntryId;
                    }
                } catch (err) {
                    this.logger.error({ msg: 'Failed to process history entry', account: this.account, entry, err });
                }
            }

            if (Number(historyRes?.historyId) > newestHistoryId) {
                newestHistoryId = Number(historyRes.historyId);
            }

            if (historyRes?.nextPageToken) {
                await getHistoryPage(historyRes?.nextPageToken);
            }
        };

        await getHistoryPage();

        if (newestHistoryId && newestHistoryId > currentHistoryId) {
            await this.redis.hset(this.getAccountKey(), 'googleHistoryId', newestHistoryId.toString());
        }
    }

    async prepareNewMessage(eventEntry, options) {
        this.logger.debug({ msg: 'New message', id: eventEntry.id, flags: eventEntry.flags && Array.from(eventEntry.flags) });

        if (options.fetchHeaders) {
            options.headers = options.fetchHeaders;
        } else {
            options.headers = 'headers' in options ? options.headers : false;
        }

        let messageData = await this.getMessage(eventEntry.id, options);

        if (!messageData) {
            await this.notify(this, MESSAGE_MISSING_NOTIFY, {
                id: eventEntry.id
            });
            return;
        }

        // All new emails are "new" as message movement between folders is reported as label changes
        messageData.seemsLikeNew = true;

        if (eventEntry.category) {
            messageData.category = eventEntry.category;
        }

        for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
            if (this.listingEntry.specialUse === specialUseTag || (messageData.labels && messageData.labels.includes(specialUseTag))) {
                messageData.messageSpecialUse = specialUseTag;
                break;
            }
        }

        return messageData;
    }

    async getLocale() {
        let languageRes;
        try {
            languageRes = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/settings/language`, 'get');
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                default:
                    throw err;
            }
        }

        return (languageRes?.displayLanguage || '').toString().split(/[-_]/).shift().trim().toLowerCase();
    }

    async listSignatures() {
        let signatureListRes;
        try {
            signatureListRes = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/settings/sendAs`, 'get');
        } catch (err) {
            switch (err?.oauthRequest?.response?.error?.code) {
                default:
                    throw err;
            }
        }

        let signatures = signatureListRes?.sendAs?.map(entry => ({ address: entry.sendAsEmail, signature: entry.signature })).filter(entry => entry.signature);

        return { signatures, signaturesSupported: true };
    }
}

module.exports = { GmailClient };
