'use strict';

const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const { checkAccountScopes } = require('../oauth/scope-checker');
const getSecret = require('../get-secret');
const msgpack = require('msgpack5')();
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');
const he = require('he');
const { BaseClient, metricsMeta } = require('./base-client');
const { mimeHtml } = require('@postalsys/email-text-tools');
const { emitChangeEvent } = require('../tools');
const crypto = require('crypto');
const { Gateway } = require('../gateway');

const {
    MESSAGE_UPDATED_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_MISSING_NOTIFY,
    EMAIL_SENT_NOTIFY,
    REDIS_PREFIX,
    AUTH_ERROR_NOTIFY,
    AUTH_SUCCESS_NOTIFY,
    DEFAULT_GMAIL_EXPORT_BATCH_SIZE
} = require('../consts');

const settings = require('../settings');

const { GMAIL_API_BASE, LIST_BATCH_SIZE, request: gmailApiRequest } = require('./gmail/gmail-api');

const MAX_GMAIL_BATCH_SIZE = 50;

// Labels to exclude from folder listings
const SKIP_LABELS = ['UNREAD', 'STARRED', 'IMPORTANT', 'CHAT', 'CATEGORY_PERSONAL'];

// Maps Gmail system labels to IMAP special-use flags
const SYSTEM_LABELS = {
    SENT: '\\Sent',
    INBOX: '\\Inbox',
    TRASH: '\\Trash',
    DRAFT: '\\Drafts',
    SPAM: '\\Junk',
    IMPORTANT: '\\Important'
};

// User-friendly names for system labels
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

// Reverse mapping for IMAP special-use to Gmail labels
const SYSTEM_LABELS_REV = {};
for (let label of Object.keys(SYSTEM_LABELS)) {
    SYSTEM_LABELS_REV[SYSTEM_LABELS[label]] = label;
}

// Timing constants for Gmail Pub/Sub watch
const RENEW_WATCH_TTL = 60 * 60 * 1000; // 1h - how often to check if watch needs renewal
const MIN_WATCH_TTL = 24 * 3600 * 1000; // 1day - minimum time before renewing watch
const FALLBACK_POLLING_INTERVAL = 10 * 60 * 1000; // 10min - fallback polling if no Pub/Sub notifications

/*
Gmail API implementation status:

✅ listMessages - with cursor-based pagination
✅ getText
✅ getMessage
✅ updateMessage
✅ updateMessages
✅ listMailboxes
✅ moveMessage
✅ moveMessages
✅ deleteMessage - no force option (moves to trash)
✅ deleteMessages - no force option (moves to trash)
✅ getRawMessage
🟡 getQuota - not supported by Gmail API
✅ createMailbox
✅ renameMailbox
✅ deleteMailbox
✅ getAttachment
✅ submitMessage
✅ uploadMessage
🟡 subconnections - not supported (no IDLE equivalent)
*/

/**
 * Handles cursor-based pagination for Gmail API
 * Gmail uses pageTokens, but we wrap them in a more complex cursor
 * to support backward pagination and multiple pages
 */
class PageCursor {
    static create(cursorStr) {
        return new PageCursor(cursorStr);
    }

    constructor(cursorStr) {
        this.type = 'gmail';
        this.cursorList = []; // Array of page tokens for navigation history
        this.cursorStr = '';

        if (cursorStr) {
            // Extract cursor type prefix
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

            // Decode cursor data
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

    /**
     * Gets current page information from cursor
     * @returns {Object} Current page details
     */
    currentPage() {
        if (this.cursorList.length < 1) {
            return { page: 0, cursor: '', pageCursor: '' };
        }

        return { page: this.cursorList.length, cursor: this.decodeCursorValue(this.cursorList.at(-1)), pageCursor: this.cursorStr };
    }

    /**
     * Creates cursor for next page
     * @param {string} nextPageCursor - Gmail's nextPageToken
     * @returns {string|null} Encoded cursor string
     */
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

    /**
     * Creates cursor for previous page by removing last page token
     * @returns {string|null} Encoded cursor string
     */
    prevPageCursor() {
        if (this.cursorList.length < 1) {
            return null;
        }

        return this.type + '_' + msgpack.encode(this.cursorList.slice(0, this.cursorList.length - 1)).toString('base64url');
    }

    /**
     * Encodes a cursor value (page token) for storage
     * Handles very large numeric IDs by chunking them
     * @param {string} cursor - Page token to encode
     * @returns {Buffer|Array<Buffer>} Encoded cursor
     */
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

    /**
     * Decodes a stored cursor value back to page token
     * @param {Buffer|Array<Buffer>} value - Encoded cursor
     * @returns {string|null} Decoded page token
     */
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

/**
 * Gmail-specific email client implementation
 * Uses Gmail API instead of IMAP for better performance and features
 */
class GmailClient extends BaseClient {
    constructor(account, options) {
        super(account, options);

        this.cachedAccessToken = null;
        this.cachedAccessTokenRaw = null;

        // pseudo path for webhooks - Gmail doesn't have folders like IMAP
        this.path = '\\All';
        this.listingEntry = { specialUse: '\\All' };

        this.processingHistory = null;
        this.renewWatchTimer = null;

        this.cachedLabels = null;
    }

    /**
     * Makes authenticated request to Gmail API
     * Handles token refresh and rate limit retries automatically
     * @param {string} url - API endpoint URL
     * @param {string} [method='get'] - HTTP method
     * @param {*} [payload] - Request payload
     * @param {Object} [options={}] - Request options
     * @returns {Object} API response
     */
    async request(url, method, payload, options) {
        return gmailApiRequest(this, url, method, payload, options);
    }

    // PUBLIC METHODS

    /**
     * Initializes Gmail connection and sets up real-time notifications
     * @param {Object} opts - Initialization options
     */
    async init(opts) {
        opts = opts || {};

        this.state = 'connecting';
        await this.setStateVal();

        await this.getAccount();
        await this.getClient(true);

        // Ensure access token exists to get scopes
        let accountData;
        try {
            await this.getToken();
            // Reload account data after getting access token to ensure we have the latest OAuth2 scopes
            accountData = await this.accountObject.loadAccountData(this.account);
        } catch (err) {
            this.logger.error({
                msg: 'Failed to get token or reload account data during init',
                account: this.account,
                err
            });
            throw err;
        }

        // Check if send-only mode
        const scopes = accountData.oauth2?.accessToken?.scope || accountData.oauth2?.scope || [];
        const { hasSendScope, hasReadScope } = checkAccountScopes('gmail', scopes);
        const isSendOnly = hasSendScope && !hasReadScope;

        this.logger.info({
            msg: 'Account scopes loaded',
            account: this.account,
            scopes,
            hasSendScope,
            hasReadScope,
            isSendOnly
        });

        if (!isSendOnly) {
            // Set up Gmail Pub/Sub watch for real-time notifications (not needed for send-only)
            await this.renewWatch(accountData, opts);
        }

        // Fetch user profile to verify authentication
        let profileRes;
        let userInfoRes;
        try {
            if (isSendOnly) {
                // For send-only accounts, use Google UserInfo endpoint which works with openid/email/profile scopes
                userInfoRes = await this.request(`https://www.googleapis.com/oauth2/v2/userinfo`, 'get');
            } else {
                // For full access accounts, use Gmail profile endpoint to also get historyId
                profileRes = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/profile`);
            }
        } catch (err) {
            this.state = 'authenticationError';
            await this.setStateVal();

            err.authenticationFailed = true;

            if (!err.errorNotified) {
                err.errorNotified = true;
                await this.notify(false, AUTH_ERROR_NOTIFY, {
                    response: err.oauthRequest?.response?.error?.message || err.response,
                    serverResponseCode: 'ApiRequestError'
                });
            }

            throw err;
        }

        let updates = {};

        // Update account email if changed
        if (isSendOnly) {
            // Extract email from UserInfo response for send-only accounts
            if (userInfoRes?.email && accountData.oauth2.auth?.user !== userInfoRes.email) {
                updates._oldOAuth2User = accountData.oauth2.auth?.user;
                updates.oauth2 = {
                    partial: true,
                    auth: Object.assign(accountData.oauth2.auth || {}, {
                        user: userInfoRes.email
                    })
                };
            }
        } else {
            // Extract email from profile for full access accounts
            if (profileRes.emailAddress && accountData.oauth2.auth?.user !== profileRes.emailAddress) {
                updates._oldOAuth2User = accountData.oauth2.auth?.user; // needed for cleanups
                updates.oauth2 = {
                    partial: true,
                    auth: Object.assign(accountData.oauth2.auth || {}, {
                        // update username
                        user: profileRes.emailAddress
                    })
                };
            }
        }

        // Detect and store user locale (only for full access accounts)
        if (!accountData.locale && !isSendOnly) {
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
            msg: isSendOnly ? 'Initializing Gmail send-only account' : 'Initializing Gmail account',
            provider: accountData.oauth2.provider,
            user: accountData.oauth2.auth?.user,
            sendOnly: isSendOnly
        });

        // Ensure Pub/Sub subscription mapping is correct
        if (
            accountData.oauth2.auth?.user &&
            (await this.redis.hget(`${REDIS_PREFIX}oapp:h:${accountData.oauth2.provider}`, accountData.oauth2.auth?.user?.toLowerCase())) !== this.account
        ) {
            await this.redis.hset(`${REDIS_PREFIX}oapp:h:${accountData.oauth2.provider}`, accountData.oauth2.auth?.user?.toLowerCase(), this.account);
            this.logger.info({ msg: 'Re-set missing Google Pub/Sub subscription', account: this.account, emailAddress: accountData.oauth2.auth?.user });
        }

        if (!isSendOnly) {
            // Check and process history changes since last sync (only for full access accounts)
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

            // Schedule periodic watch renewal (only for full access accounts)
            this.setupRenewWatchTimer();

            // Schedule fallback polling in case Pub/Sub notifications are dropped
            this.lastNotificationTime = Date.now();
            this.setupFallbackPollingTimer();
        }

        // Determine if this is a reconnection after error
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

        // Send appropriate authentication success notification
        if (isFirstSuccessfulConnection) {
            this.logger.info({ msg: 'Successful login without a previous active session', account: this.account, isiInitial, prevActive: false });
            await this.notify(false, AUTH_SUCCESS_NOTIFY, {
                user: accountData.oauth2?.auth?.user
            });
        } else {
            this.logger.info({ msg: 'Successful login with a previous active session', account: this.account, isiInitial, prevActive: true });
        }

        // Clear any previous error state
        await this.redis.hdel(this.getAccountKey(), 'lastErrorState', 'lastError:errorCount', 'lastError:first');
        await emitChangeEvent(this.logger, this.account, 'state', this.state);
    }

    /**
     * Closes Gmail connection and stops watch renewal
     */
    async close() {
        clearTimeout(this.renewWatchTimer);
        clearTimeout(this.fallbackPollingTimer);
        this.closed = true;

        // Clean up cached data
        this.cachedLabels = null;
        this.cachedLabelsTime = null;
        this.pendingHistoryId = null;

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
        clearTimeout(this.fallbackPollingTimer);
        this.closed = true;

        // Clean up cached data
        this.cachedLabels = null;
        this.cachedLabelsTime = null;
        this.pendingHistoryId = null;

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

    /**
     * Lists Gmail labels as IMAP-style mailboxes
     * @param {Object} options - Listing options including status query
     * @returns {Array} Array of mailbox objects
     */
    async listMailboxes(options) {
        await this.prepare();

        let labelsResult = await this.getLabels();

        // Filter out system labels we don't want to show
        let labels = labelsResult.filter(label => !SKIP_LABELS.includes(label.id));

        let resultLabels;
        if (options && options.statusQuery?.unseen) {
            // Fetch detailed label info including message counts
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

            // Batch API requests for efficiency
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

        // Convert Gmail labels to IMAP-style mailbox structure
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

                // Map system labels to IMAP special-use flags
                if (label.type === 'system' && SYSTEM_LABELS.hasOwnProperty(label.id)) {
                    folderData.specialUse = SYSTEM_LABELS[label.id];
                    folderData.specialUseSource = 'extension';
                }

                // Hide category labels (they appear as tabs in Gmail UI)
                if (label.type === 'system' && /^CATEGORY/.test(label.id)) {
                    return false;
                }

                // Include message counts if requested
                if (!isNaN(label.messagesTotal) && options?.statusQuery?.messages) {
                    folderData.status = {
                        messages: Number(label.messagesTotal) || 0,
                        unseen: Number(label.messagesUnread) || 0
                    };
                }

                return folderData;
            })
            .filter(value => value);

        // Add virtual "All Mail" folder for Gmail API
        // This allows exporting all messages without scanning individual labels
        mailboxes.unshift({
            id: 'virtual_all',
            path: '\\All',
            delimiter: '/',
            parentPath: '',
            name: 'All Mail',
            listed: true,
            subscribed: false,
            noSelect: true,
            specialUse: '\\All',
            specialUseSource: 'extension'
        });

        mailboxes.sort((a, b) => {
            // Sort: INBOX first, then special folders, then alphabetical
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

    /**
     * Lists messages with Gmail API, supporting search and pagination
     * @param {Object} query - Search and pagination parameters
     * @param {Object} options - Additional options
     * @returns {Object} Paginated message list
     */
    async listMessages(query, options) {
        options = options || {};

        await this.prepare();

        // Gmail doesn't support numeric page numbers, only cursors
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
            // Convert path to Gmail label ID
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
                // Threading is a special case - fetch entire thread
                let threadListingResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/threads/${query.search.threadId}`, 'get', {
                    format: 'full'
                });

                let messageCount = threadListingResult?.messages?.length || 0;
                let currentPage = pageCursor.currentPage();

                let nextPageToken = null;
                if (messageCount > pageSize) {
                    // Handle pagination within thread
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

            // Convert IMAP-style search to Gmail query
            // NB! Might throw if using unsupported search terms
            const preparedQuery = this.prepareQuery(query.search);
            if (preparedQuery) {
                requestQuery.q = this.prepareQuery(query.search);
            }
        }

        // Apply pagination cursor
        let currentPage = pageCursor.currentPage();
        if (currentPage?.cursor) {
            requestQuery.pageToken = currentPage.cursor;
        }

        // Fetch message list
        let listingResult = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages`, 'get', requestQuery);
        let messageCount = listingResult.resultSizeEstimate;

        let pages = Math.ceil(messageCount / pageSize);

        let nextPageCursor = pageCursor.nextPageCursor(listingResult.nextPageToken);
        let prevPageCursor = pageCursor.prevPageCursor();

        if (options.metadataOnly || query.metadataOnly) {
            // Return just IDs without fetching full content
            return {
                total: messageCount,
                page: currentPage.page,
                pages,
                nextPageCursor,
                prevPageCursor,
                messages: listingResult.messages
            };
        }

        // Fetch message content for matching messages in batches
        // Use format=minimal for minimalFields option (faster, returns only id, threadId, labelIds, internalDate, sizeEstimate)
        const messageFormat = options.minimalFields ? 'minimal' : undefined;

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
                    messageList.push(this.formatMessage(entry.value, { path, minimalFields: options.minimalFields }));
                }
            }
            promises = [];
        };

        for (let { id: message } of listingResult.messages || []) {
            let requestUrl = `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${message}`;
            let requestParams = messageFormat ? { format: messageFormat } : undefined;
            promises.push(this.request(requestUrl, 'get', requestParams));
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

    /**
     * Fetches raw RFC822 message content
     * @param {string} emailId - Gmail message ID
     * @returns {Buffer} Raw message buffer
     */
    async getRawMessage(emailId) {
        await this.prepare();

        const requestQuery = {
            format: 'raw'
        };
        const result = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}`, 'get', requestQuery);

        return result?.raw ? Buffer.from(result?.raw, 'base64url') : null;
    }

    /**
     * Deletes a message (moves to trash in Gmail)
     * @param {string} emailId - Message ID
     * @returns {Object} Deletion result
     */
    async deleteMessage(emailId /*, force*/) {
        await this.prepare();

        // Gmail doesn't permanently delete, just moves to trash
        const url = `${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}/trash`;
        const result = await this.request(url, 'post', Buffer.alloc(0));

        return {
            deleted: result && result.labelIds?.includes('TRASH'),
            moved: {
                message: result.id
            }
        };
    }

    /**
     * Deletes multiple messages matching criteria
     * @param {string} path - Source folder path
     * @param {Object} search - Search criteria
     * @returns {Object} Deletion result
     */
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

        // Add TRASH label and remove source label
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

    /**
     * Updates flags and labels for a single message
     * @param {string} emailId - Message ID
     * @param {Object} updates - Flags and labels to update
     * @returns {Object} Update result with final state
     */
    async updateMessage(emailId, updates) {
        await this.prepare();
        updates = updates || {};

        let addLabelIds = new Set();
        let removeLabelIds = new Set();

        // Convert IMAP flags to Gmail labels
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

        // Process direct label updates
        if (updates.labels) {
            for (let label of [].concat(updates.labels.add || [])) {
                // Convert IMAP special-use to Gmail label
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

        // Return final state after update
        let { flags: messageFlags, labels: messageLabels } = this.formatFlagsAndLabels(modifyResult);

        let response = {
            flags: Object.assign({}, updates.flags || {}, { result: messageFlags || [] }),
            labels: Object.assign({}, updates.labels || {}, { result: messageLabels || [] })
        };

        return response;
    }

    /**
     * Updates multiple messages matching search criteria
     * @param {string} path - Source folder path
     * @param {Object} search - Search criteria
     * @param {Object} updates - Updates to apply
     * @returns {Object} Update result
     */
    async updateMessages(path, search, updates) {
        await this.prepare();
        updates = updates || {};

        // Step 1. Resolve matching messages
        let messages = [];
        let cursor;

        let maxMessages = 1000;
        let notDone = true;

        // Fetch all matching messages (up to limit)
        while (notDone && !search.emailIds) {
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

        let emailIds = search.emailIds || messages.map(message => message.id);

        if (!emailIds?.length) {
            // nothing to do here
            return updates;
        }

        let addLabelIds = new Set();
        let removeLabelIds = new Set();

        // Convert flags to label operations
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

        // Batch modify all messages
        await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/batchModify`, 'post', labelUpdates, { returnText: true });

        return Object.assign({}, updates, {
            emailIds
        });
    }

    /**
     * Moves a message between folders (labels)
     * @param {string} emailId - Message ID
     * @param {Object} target - Target folder
     * @param {Object} options - Move options
     * @returns {Object} Move result
     */
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

    /**
     * Moves multiple messages between folders
     * @param {string} source - Source folder path
     * @param {Object} search - Search criteria
     * @param {Object} target - Target folder
     * @returns {Object} Move result
     */
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

    /**
     * Downloads attachment content
     * @param {string} attachmentId - Encoded attachment identifier
     * @returns {Object} Attachment data with headers
     */
    async getAttachment(attachmentId) {
        let attachmentData = await this.getAttachmentContent(attachmentId);

        if (!attachmentData || !attachmentData.content) {
            return false;
        }

        // Generate proper Content-Disposition header with filename
        let filenameParam = '';
        if (attachmentData.filename) {
            let isCleartextFilename = attachmentData.filename && /^[a-z0-9 _\-()^[\]~=,+*$]+$/i.test(attachmentData.filename);
            if (isCleartextFilename) {
                filenameParam = `; filename=${JSON.stringify(attachmentData.filename)}`;
            } else {
                // Use RFC 5987 encoding for non-ASCII filenames
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

    /**
     * Fetches full message data with optional enhancements
     * @param {string} emailId - Message ID
     * @param {Object} options - Fetch options
     * @returns {Object} Complete message data
     */
    async getMessage(emailId, options) {
        options = options || {};
        await this.prepare();

        // Enable all enhancements for web-safe HTML
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

        // Resolve label IDs to human-readable names
        await this.resolveLabels(formattedMessage);

        // Mark as seen if requested
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

        // Generate web-safe HTML if requested
        if (options.preProcessHtml && formattedMessage.text && (formattedMessage.text.html || formattedMessage.text.plain)) {
            formattedMessage.text.html = mimeHtml({
                html: formattedMessage.text.html,
                text: formattedMessage.text.plain
            });
            formattedMessage.text.webSafe = true;
        }

        // Embed inline images as data URIs
        if (options.embedAttachedImages && formattedMessage.text?.html && formattedMessage.attachments) {
            let attachmentMap = new Map();

            // Find CID references in HTML
            for (let attachment of formattedMessage.attachments) {
                let contentId = attachment.contentId && attachment.contentId.replace(/^<|>$/g, '');
                if (contentId && formattedMessage.text.html.indexOf(contentId) >= 0) {
                    attachmentMap.set(contentId, { attachment, content: null });
                }
            }

            // Download referenced attachments
            for (let entry of attachmentMap.values()) {
                if (!entry.content) {
                    entry.content = await this.getAttachmentContent(entry.attachment.id);
                }
            }

            // Replace CID references with data URIs
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

    /**
     * Fetches multiple messages in parallel for batch export operations
     * @param {string[]} emailIds - Array of message IDs
     * @param {Object} options - Fetch options
     * @returns {Object[]} Array of results with messageId, data, and error fields
     */
    async getMessages(emailIds, options) {
        options = options || {};
        await this.prepare();

        // Pre-fetch labels to resolve label IDs to names
        const labelMap = new Map();
        try {
            const labelsResult = await this.getLabels();
            for (const label of labelsResult || []) {
                labelMap.set(label.id, label.name);
            }
        } catch (err) {
            this.logger.warn({ msg: 'Failed to fetch labels for export, using raw label IDs', account: this.account, err });
        }

        const results = [];
        const settingsBatchSize = await settings.get('gmailExportBatchSize');
        const batchSize = Math.min(settingsBatchSize || DEFAULT_GMAIL_EXPORT_BATCH_SIZE, MAX_GMAIL_BATCH_SIZE);

        for (let i = 0; i < emailIds.length; i += batchSize) {
            const batch = emailIds.slice(i, i + batchSize);

            const batchResults = await Promise.all(
                batch.map(async emailId => {
                    try {
                        const requestQuery = { format: 'full' };
                        const messageData = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${emailId}`, 'get', requestQuery);
                        const formattedMessage = this.formatMessage(messageData, { extended: true, textType: options.textType });

                        await this.resolveLabels(formattedMessage, labelMap);

                        return {
                            messageId: emailId,
                            data: formattedMessage,
                            error: null
                        };
                    } catch (err) {
                        return {
                            messageId: emailId,
                            data: null,
                            error: { message: err.message, code: err.code, statusCode: err.statusCode }
                        };
                    }
                })
            );

            results.push(...batchResults);
        }

        return results;
    }

    /**
     * Fetches text content for a message
     * @param {string} textId - Encoded text identifier
     * @param {Object} options - Text options
     * @returns {Object} Text content
     */
    async getText(textId, options) {
        options = options || {};
        await this.prepare();

        // Decode text part references
        const [emailId, textParts] = msgpack.decode(Buffer.from(textId, 'base64url'));

        const bodyParts = new Map();

        // Map part IDs to content types
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

        // Walk message structure to find text parts
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

        // Concatenate text parts
        for (let key of Object.keys(textContent)) {
            response[key] = textContent[key].map(buf => buf.toString()).join('\n');
        }

        response.hasMore = false;

        return response;
    }

    /**
     * Uploads a new message to Gmail
     * @param {Object} data - Message data
     * @returns {Object} Upload result
     */
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

        // Generate raw message
        let { raw, messageId, referencedMessage, documentStoreUsed } = await this.prepareRawMessage(data);
        if (raw?.buffer) {
            // convert from a Uint8Array to a Buffer
            raw = Buffer.from(raw);
        }

        let payload = {
            labelIds: [targetLabel.id],
            raw: raw.toString('base64url')
        };

        // Maintain thread if replying
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

    /**
     * Sends a message via Gmail API or SMTP gateway
     * @param {Object} data - Message data
     * @returns {Object} Send result
     */
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

        let { raw, messageId, queueId, job: jobData, envelope } = data;

        if (raw?.buffer) {
            // convert from a Uint8Array to a Buffer
            raw = Buffer.from(raw);
        }

        // Check if using external SMTP gateway
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
            // Send via SMTP gateway instead
            return await super.submitMessage(data);
        }

        // Verify job still exists
        const submitJobEntry = await this.submitQueue.getJob(jobData.id);
        if (!submitJobEntry) {
            // already failed?
            this.logger.error({
                msg: 'Submit job was not found',
                job: jobData.id
            });
            return false;
        }

        // Gmail JSON endpoint: 5MB body limit (~3.5MB raw before base64url overhead)
        // Gmail upload endpoint: 35MB raw RFC822
        let contentType;
        let payload;
        let targetEndpoint;
        const JSON_SEND_LIMIT = 3.5 * 1024 * 1024;

        if (raw.length <= JSON_SEND_LIMIT) {
            // JSON endpoint with base64url encoding (retry-safe, no ArrayBuffer issues)
            contentType = 'application/json';
            payload = { raw: raw.toString('base64url') };
            targetEndpoint = `/gmail/v1/users/me/messages/send`;
            if (data?.reference?.threadId) {
                payload.threadId = data.reference.threadId;
            }
        } else if (data?.reference?.threadId) {
            // Large threaded reply: multipart upload preserves explicit threadId
            // via JSON metadata alongside the raw RFC822 message body
            const boundary = `ee_${crypto.randomBytes(16).toString('hex')}`;
            const metadata = JSON.stringify({ threadId: data.reference.threadId });
            const preamble = Buffer.from(
                `--${boundary}\r\n` +
                    `Content-Type: application/json; charset=UTF-8\r\n` +
                    `\r\n` +
                    `${metadata}\r\n` +
                    `--${boundary}\r\n` +
                    `Content-Type: message/rfc822\r\n` +
                    `\r\n`
            );
            const epilogue = Buffer.from(`\r\n--${boundary}--`);

            contentType = `multipart/related; boundary=${boundary}`;
            payload = Buffer.concat([preamble, raw, epilogue]);
            targetEndpoint = `/upload/gmail/v1/users/me/messages/send?uploadType=multipart`;
        } else {
            // Large non-threaded message: simple upload with raw RFC822 Buffer
            contentType = 'message/rfc822';
            payload = raw;
            targetEndpoint = `/upload/gmail/v1/users/me/messages/send`;
        }

        // Send via Gmail API
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
            // Detect send-only mode using centralized scope checker
            const scopes = accountData.oauth2?.accessToken?.scope || accountData.oauth2?.scope || [];
            const { hasSendScope, hasReadScope } = checkAccountScopes('gmail', scopes);
            const isSendOnly = hasSendScope && !hasReadScope;

            if (!isSendOnly) {
                // fetch message data to get actual Message-ID value (requires read scope)
                let messageEntry = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/messages/${submitInfo?.id}`, 'get', {
                    format: 'metadata',
                    metadataHeaders: 'message-id'
                });
                let messageIdHeader = messageEntry?.payload?.headers?.find(h => /^Message-ID$/i.test(h.name));
                gmailMessageId = messageIdHeader?.value;
            } else {
                // For send-only accounts, use the original messageId since we can't read messages back
                gmailMessageId = messageId;
            }
        }

        try {
            // try to update job progress
            await submitJobEntry.updateProgress({
                status: 'smtp-completed',
                messageId: gmailMessageId,
                originalMessageId: messageId
            });
        } catch (err) {
            // ignore
        }

        // Send success notification
        await this.notify(false, EMAIL_SENT_NOTIFY, {
            messageId: gmailMessageId,
            originalMessageId: messageId,
            queueId,
            envelope
        });

        // Update feedback key if provided
        if (data.feedbackKey) {
            await this.redis
                .multi()
                .hset(data.feedbackKey, 'success', 'true')
                .expire(data.feedbackKey, 1 * 60 * 60)
                .exec();
        }

        return {
            messageId: gmailMessageId
        };
    }

    /**
     * Creates a new Gmail label (folder)
     * @param {string} path - Label path
     * @returns {Object} Creation result
     */
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

    /**
     * Modifies a Gmail label (rename only, subscription is ignored for Gmail)
     * @param {string} path - Current path
     * @param {string} newPath - New path (optional)
     * @param {boolean} subscribed - Ignored for Gmail API
     * @returns {Object} Modify result
     */
    async modifyMailbox(path, newPath, subscribed) {
        // Gmail API does not support subscription management, so we ignore the subscribed parameter
        // If no newPath provided, just return the current path without changes
        if (!newPath) {
            return {
                path: [].concat(path || []).join('/'),
                renamed: false
            };
        }

        return await this.renameMailbox(path, newPath);
    }

    /**
     * Renames a Gmail label
     * @param {string} path - Current path
     * @param {string} newPath - New path
     * @returns {Object} Rename result
     */
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

    /**
     * Deletes a Gmail label
     * @param {string} path - Label path
     * @returns {Object} Deletion result
     */
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

    /**
     * Handles external notifications from Gmail Pub/Sub
     * @param {Object} message - Pub/Sub message
     * @returns {boolean} Processing result
     */
    async externalNotify(message) {
        // Track notification time for fallback polling
        this.lastNotificationTime = Date.now();

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
        let tokenData;
        try {
            tokenData = await this.accountObject.getActiveAccessTokenData();
            if (!['init', 'connecting', 'connected'].includes(this.state)) {
                // We're in an error state (authenticationError, disconnected, etc.)
                // But we just got a valid token, so we've recovered
                this.state = 'connected';
                await this.setStateVal();
            }

            // Track successful token refresh (only if token was actually refreshed, not cached)
            if (!tokenData.cached) {
                metricsMeta({ account: this.account }, this.logger, 'oauth2TokenRefresh', 'inc', { status: 'success', provider: 'gmail', statusCode: '200' });
            }
        } catch (E) {
            if (E.code === 'ETokenRefresh') {
                // treat as authentication failure
                this.state = 'authenticationError';
                await this.setStateVal();

                E.authenticationFailed = true;

                // Track failed token refresh
                const statusCode = String(E.statusCode || 0);
                metricsMeta({ account: this.account }, this.logger, 'oauth2TokenRefresh', 'inc', { status: 'failure', provider: 'gmail', statusCode });

                if (!E.errorNotified) {
                    E.errorNotified = true;
                    await this.notify(false, AUTH_ERROR_NOTIFY, {
                        response: E.oauthRequest?.response?.error?.message || E.response,
                        serverResponseCode: 'TokenGenerationError'
                    });
                }
            }

            throw E;
        }
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

    /**
     * Sets up timer to periodically renew Gmail watch subscription
     * Uses actual watch expiration if available for smarter scheduling
     */
    setupRenewWatchTimer() {
        if (this.closed) {
            return;
        }
        clearTimeout(this.renewWatchTimer);

        // Calculate optimal delay based on watch expiration
        let delay = RENEW_WATCH_TTL;
        if (this.watchExpiration) {
            // Renew 1 hour before expiration
            const renewAt = this.watchExpiration - 60 * 60 * 1000;
            const timeUntilRenewal = renewAt - Date.now();
            // Use the calculated time, but not less than RENEW_WATCH_TTL
            delay = Math.max(timeUntilRenewal, RENEW_WATCH_TTL);
        }

        this.renewWatchTimer = setTimeout(() => {
            if (this.closed) {
                return;
            }
            let authError = false;
            this.renewWatch()
                .catch(err => {
                    this.logger.error({ msg: 'Failed to renew Gmail subscription watch', account: this.account, err });
                    // Check if this is a permanent auth failure
                    if (err.code === 'ETokenRefresh' || this.state === 'authenticationError') {
                        authError = true;
                    }
                })
                .finally(() => {
                    // Don't restart timer on auth failures - let the auth flow handle recovery
                    if (!this.closed && !authError && this.state !== 'authenticationError') {
                        this.setupRenewWatchTimer();
                    }
                });
        }, delay);
        this.renewWatchTimer.unref();
    }

    /**
     * Sets up fallback polling timer to check for missed notifications
     * If no Pub/Sub notifications received within the interval, triggers a proactive sync
     */
    setupFallbackPollingTimer() {
        if (this.closed) {
            return;
        }
        clearTimeout(this.fallbackPollingTimer);
        this.fallbackPollingTimer = setTimeout(async () => {
            if (this.closed) {
                return;
            }

            const timeSinceNotification = Date.now() - (this.lastNotificationTime || 0);
            if (timeSinceNotification >= FALLBACK_POLLING_INTERVAL) {
                // No notifications received within the interval, do a proactive sync
                this.logger.info({
                    msg: 'No Pub/Sub notifications received, triggering fallback sync',
                    account: this.account,
                    timeSinceNotification
                });

                try {
                    const historyId = await this.redis.hget(this.getAccountKey(), 'googleHistoryId');
                    if (historyId) {
                        // Trigger sync to check for any missed changes
                        this.triggerSync(Number(historyId), Number(historyId));
                    }
                } catch (err) {
                    this.logger.error({
                        msg: 'Failed to trigger fallback sync',
                        account: this.account,
                        err
                    });
                }
            }

            // Restart the timer
            if (!this.closed && this.state !== 'authenticationError') {
                this.setupFallbackPollingTimer();
            }
        }, FALLBACK_POLLING_INTERVAL);
        this.fallbackPollingTimer.unref();
    }

    /**
     * Renews Gmail Pub/Sub watch subscription
     * @param {Object} accountData - Account data
     * @param {Object} opts - Renewal options
     */
    async renewWatch(accountData, opts) {
        let { forceWatchRenewal } = opts || {};

        if (!accountData) {
            await this.getAccount();
            accountData = await this.accountObject.loadAccountData(this.account, false);
        }

        let now = Date.now();

        // Check if renewal is needed
        if (accountData._app?.pubSubApp && (forceWatchRenewal || !accountData.lastWatch || accountData.lastWatch < new Date(now - MIN_WATCH_TTL))) {
            let appData = await oauth2Apps.get(accountData._app?.pubSubApp);
            if (appData?.pubSubTopic && appData.pubSubIamPolicy) {
                await this.prepare();
                try {
                    // Request Gmail to send notifications to Pub/Sub topic
                    let watchResponse = await this.request(`${GMAIL_API_BASE}/gmail/v1/users/me/watch`, 'post', {
                        topicName: appData?.pubSubTopic
                    });
                    // { historyId: '3663748', expiration: '1720183655953' }

                    // Store expiration for smarter renewal scheduling
                    const watchExpiration = watchResponse?.expiration ? Number(watchResponse.expiration) : null;
                    this.watchExpiration = watchExpiration;

                    await this.accountObject.update({
                        lastWatch: new Date(now),
                        watchResponse,
                        watchExpiration,
                        watchFailure: null
                    });
                    this.logger.info({
                        msg: 'Renewed Gmail pubsub watch',
                        account: this.account,
                        watchResponse,
                        watchExpiration: watchExpiration ? new Date(watchExpiration).toISOString() : null
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

    /**
     * Fetches all Gmail labels with caching
     * @param {boolean} force - Force refresh
     * @returns {Array} Label list
     */
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

    /**
     * Resolves label IDs to human-readable names on a formatted message.
     * Mutates formattedMessage.labels in place. Labels starting with '\\' are
     * treated as special-use labels and left as-is.
     *
     * @param {Object} formattedMessage - Message with a .labels array
     * @param {Map} [labelMap] - Optional pre-built id-to-name map (avoids an extra getLabels call)
     */
    async resolveLabels(formattedMessage, labelMap) {
        if (!Array.isArray(formattedMessage?.labels)) {
            return;
        }

        if (!labelMap) {
            const labelsResult = await this.getLabels();
            labelMap = new Map();
            for (const label of labelsResult || []) {
                labelMap.set(label.id, label.name);
            }
        }

        formattedMessage.labels = formattedMessage.labels.map(label => {
            if (label.startsWith('\\')) {
                return label;
            }
            return labelMap.get(label) || label;
        });
    }

    /**
     * Resolves a label by path or ID
     * @param {string} path - Label path or ID
     * @returns {Object|false} Label object or false if not found
     */
    async getLabel(path) {
        path = []
            .concat(path || '')
            .join('/')
            .replace(/^INBOX(\/|$)/gi, 'INBOX');

        // Try system label mappings first
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

    /**
     * Extracts envelope data from Gmail message
     * @param {Object} messageData - Gmail message object
     * @returns {Object} Envelope with parsed addresses
     */
    getEnvelope(messageData) {
        let envelope = {};

        // Parse address headers
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

    /**
     * Extracts attachments and text parts from message structure
     * @param {Object} messageData - Gmail message
     * @param {Object} options - Processing options
     * @returns {Object} Attachments and text information
     */
    getAttachmentList(messageData, options) {
        options = options || {};

        let encodedTextSize = {};
        const attachments = [];
        const textParts = [[], [], []]; // [plain, html, other]
        const textContents = [[], [], []];

        /**
         * Recursively walks message MIME structure
         * @param {Object} node - MIME part node
         * @param {boolean} isRelated - Whether part is inside multipart/related
         */
        let walk = (node, isRelated) => {
            if (node.mimeType === 'multipart/related') {
                isRelated = true;
            }

            // Parse content headers
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
                    // This is an attachment
                    const attachmentIdProps = [
                        messageData.id,
                        node.mimeType || null,
                        disposition?.value || null,
                        node.filename || null,
                        node.body.attachmentId
                    ];

                    const attachment = {
                        // Create stable attachment ID
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

                    // Calendar method for iCal
                    if (typeof contentType?.params?.method === 'string') {
                        attachment.method = contentType.params.method;
                    }

                    attachments.push(attachment);
                } else if ((!disposition || disposition.value === 'inline') && /^text\/(plain|html)/.test(node.mimeType)) {
                    // This is a text part
                    let type = node.mimeType.substr(5);
                    if (!encodedTextSize[type]) {
                        encodedTextSize[type] = 0;
                    }
                    encodedTextSize[type] += node.body.size;

                    // Track part IDs and optionally extract content
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

            // Process child parts
            if (node.parts) {
                node.parts.forEach(childNode => walk(childNode, isRelated));
            }
        };

        walk(messageData.payload, false);

        // Concatenate text parts
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

    /**
     * Converts Gmail labels to IMAP-style flags and labels
     * @param {Object} messageData - Gmail message
     * @returns {Object} Flags, labels, and category
     */
    formatFlagsAndLabels(messageData) {
        messageData = messageData || {};

        let flags = [];
        let labels = [];
        let category;

        // Convert Gmail labels to IMAP flags
        if (!messageData.labelIds?.includes('UNREAD')) {
            flags.push('\\Seen');
        }

        if (messageData.labelIds?.includes('STARRED')) {
            flags.push('\\Flagged');
        }

        if (messageData.labelIds?.includes('DRAFTS')) {
            flags.push('\\Draft');
        }

        // Process labels
        for (let label of messageData.labelIds || []) {
            if (SKIP_LABELS.includes(label)) {
                continue;
            }
            if (SYSTEM_LABELS.hasOwnProperty(label)) {
                labels.push(SYSTEM_LABELS[label]);
            } else if (SYSTEM_NAMES.hasOwnProperty(label) && /^CATEGORY/.test(label)) {
                // Extract category name
                category = label.split('_').pop().toLowerCase();
            } else {
                labels.push(label);
            }
        }

        // Default to primary category if in inbox
        if (!category && labels.includes('\\Inbox')) {
            category = 'primary';
        }

        return { flags, labels, category };
    }

    /**
     * Formats Gmail message to standard EmailEngine format
     * @param {Object} messageData - Raw Gmail message
     * @param {Object} options - Formatting options
     * @returns {Object} Formatted message
     */
    formatMessage(messageData, options) {
        let { extended, path, textType, minimalFields } = options || {};

        let date = messageData.internalDate && !isNaN(messageData.internalDate) ? new Date(Number(messageData.internalDate)) : undefined;
        if (date?.toString() === 'Invalid Date') {
            date = undefined;
        }

        let { flags, labels, category } = this.formatFlagsAndLabels(messageData);

        // For minimalFields mode (format=minimal), payload is not available
        // Return only basic fields: id, threadId, labelIds, internalDate, sizeEstimate
        if (minimalFields) {
            const result = {
                id: messageData.id,
                emailId: messageData.id || undefined,
                threadId: messageData.threadId || undefined,
                date: date ? date.toISOString() : undefined,
                flags,
                labels,
                category,
                unseen: !flags.includes('\\Seen') ? true : undefined,
                flagged: flags.includes('\\Flagged') ? true : undefined,
                draft: flags.includes('\\Draft') ? true : undefined,
                size: messageData.sizeEstimate
            };

            // Set special-use based on labels
            for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
                if (result.labels && result.labels.includes(specialUseTag)) {
                    result.messageSpecialUse = specialUseTag;
                    break;
                }
            }

            return result;
        }

        let envelope = this.getEnvelope(messageData);

        // Extract all headers
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

        // Decode snippet preview
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

        // Detect auto-replies
        if (this.isAutoreply(result)) {
            result.isAutoReply = true;
        }

        // Set special-use based on labels
        for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
            if (result.labels && result.labels.includes(specialUseTag)) {
                result.messageSpecialUse = specialUseTag;
                break;
            }
        }

        return result;
    }

    /**
     * Downloads attachment content from Gmail
     * @param {string} attachmentId - Encoded attachment ID
     * @param {Object} options - Download options
     * @returns {Object|Buffer} Attachment data
     */
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

    /**
     * Formats search terms for Gmail API
     * @param {*} term - Search term
     * @param {string} quot - Quote character
     * @returns {string} Formatted term
     */
    formatSearchTerm(term, quot = '"') {
        if (typeof term === 'object' && term && Object.prototype.toString.apply(term) === '[object Date]') {
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

    /**
     * Converts IMAP flags to Gmail label operations
     * @param {string} flag - IMAP flag
     * @param {boolean} remove - Whether to remove the flag
     * @returns {Object} Label operation
     */
    flagToLabel(flag, remove) {
        switch (flag) {
            case '\\Seen':
                // Gmail uses inverse logic for UNREAD label
                return { [remove ? 'add' : 'remove']: 'UNREAD' };
            case '\\Flagged':
                return { [remove ? 'remove' : 'add']: 'STARRED' };
        }
    }

    /**
     * Converts IMAP SEARCH query to Gmail API query
     * @param {Object} search - IMAP search object
     * @returns {string} Gmail query string
     */
    prepareQuery(search) {
        search = search || {};

        const queryParts = [];

        // Check for unsupported search terms
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

        // Address fields
        for (let key of ['from', 'to', 'cc', 'bcc', 'subject']) {
            if (search[key]) {
                queryParts.push(`${key}:${this.formatSearchTerm(search[key])}`);
            }
        }

        // Date ranges
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

        // Header searches
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

        // Raw Gmail query passthrough
        if (search.gmailRaw && typeof search.gmailRaw === 'string') {
            queryParts.push(search.gmailRaw);
        }

        // body search
        if (search.body && typeof search.body === 'string') {
            queryParts.push(`${this.formatSearchTerm(search.body)}`);
        }

        return queryParts.join(' ').trim();
    }

    /**
     * Triggers history sync processing
     * @param {number} currentHistoryId - Last known history ID
     * @param {number} updatedHistoryId - New history ID
     */
    triggerSync(currentHistoryId, updatedHistoryId) {
        if (this.processingHistory) {
            // Queue the latest historyId instead of dropping the notification
            this.pendingHistoryId = Math.max(this.pendingHistoryId || 0, updatedHistoryId);
            this.logger.debug({
                msg: 'Sync already in progress, queued pending historyId',
                account: this.account,
                pendingHistoryId: this.pendingHistoryId
            });
            return;
        }
        this.processingHistory = true;
        const processedHistoryId = updatedHistoryId;
        this.processHistory(currentHistoryId, updatedHistoryId)
            .catch(err => {
                this.logger.error({ msg: 'Failed to process account history', currentHistoryId, updatedHistoryId, account: this.account, err });
            })
            .finally(() => {
                this.processingHistory = false;
                // Process any queued sync notifications
                if (this.pendingHistoryId && this.pendingHistoryId > processedHistoryId) {
                    const pending = this.pendingHistoryId;
                    this.pendingHistoryId = null;
                    this.logger.debug({
                        msg: 'Processing queued historyId',
                        account: this.account,
                        fromHistoryId: processedHistoryId,
                        toHistoryId: pending
                    });
                    this.triggerSync(processedHistoryId, pending);
                } else {
                    this.pendingHistoryId = null;
                }
            });
    }

    /**
     * Processes a single history entry for changes
     * @param {Object} historyEntry - Gmail history entry
     */
    async processHistoryEntry(historyEntry) {
        let labels = await this.getLabels();

        /**
         * Processes label changes and sends update notifications
         * @param {Array} labelsValue - Label change entries
         * @param {string} direction - 'add' or 'remove'
         */
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

                // Convert label changes to flag/label changes
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

        // Process label additions and removals
        await processLabels(historyEntry?.labelsAdded, 'add');
        await processLabels(historyEntry?.labelsRemoved, 'remove');

        // Process deleted messages
        for (let entry of historyEntry?.messagesDeleted || []) {
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

        // Process new messages
        const newMessageOptions = await this.getMessageFetchOptions();
        for (let entry of historyEntry?.messagesAdded || []) {
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

    /**
     * Processes Gmail history changes since last sync
     * @param {number} currentHistoryId - Starting history ID
     * @param {number} updatedHistoryId - Target history ID
     */
    async processHistory(currentHistoryId, updatedHistoryId) {
        let newestHistoryId = currentHistoryId;
        let lastHistoryId = currentHistoryId;

        /**
         * Fetches and processes a page of history
         * @param {string} pageToken - Pagination token
         */
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
                        // History ID too old - some changes may have been missed
                        this.logger.warn({
                            msg: 'History ID too old, some email changes may have been missed',
                            account: this.account,
                            currentHistoryId,
                            updatedHistoryId,
                            err
                        });
                        // Emit warning event so the account can be flagged for attention
                        await emitChangeEvent(this.logger, this.account, 'syncWarning', {
                            type: 'historyIdExpired',
                            message: 'Some email changes may have been missed due to expired history ID'
                        });
                        // Set to newest known value
                        newestHistoryId = updatedHistoryId;
                        return;
                    }
                    default:
                        throw err;
                }
            }

            // Process each history entry
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

            // Continue with next page
            if (historyRes?.nextPageToken) {
                await getHistoryPage(historyRes?.nextPageToken);
            }
        };

        await getHistoryPage();

        // Update to newest history ID
        if (newestHistoryId && newestHistoryId > currentHistoryId) {
            await this.redis.hset(this.getAccountKey(), 'googleHistoryId', newestHistoryId.toString());
        }
    }

    /**
     * Prepares a new message for processing
     * @param {Object} eventEntry - Message event data
     * @param {Object} options - Processing options
     * @returns {Object} Prepared message data
     */
    async prepareNewMessage(eventEntry, options) {
        this.logger.debug({ msg: 'New message', id: eventEntry.id, flags: eventEntry.flags && Array.from(eventEntry.flags) });

        // Configure header fetching
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

        // Determine special-use folder
        for (let specialUseTag of ['\\Junk', '\\Sent', '\\Trash', '\\Inbox', '\\Drafts']) {
            if (this.listingEntry.specialUse === specialUseTag || (messageData.labels && messageData.labels.includes(specialUseTag))) {
                messageData.messageSpecialUse = specialUseTag;
                break;
            }
        }

        return messageData;
    }

    /**
     * Fetches user's language preference
     * @returns {string} Language code
     */
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

    /**
     * Lists email signatures from Gmail settings
     * @returns {Object} Signatures data
     */
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
