'use strict';

const { BaseClient } = require('./base-client');
const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const { emitChangeEvent } = require('../tools');

const { REDIS_PREFIX, AUTH_ERROR_NOTIFY, AUTH_SUCCESS_NOTIFY } = require('../consts');

const OUTLOOK_API_BASE = 'https://graph.microsoft.com/v1.0';

/*

❌ listMessages
  ❌ paging - cursor based
❌ getText
❌ getMessage
❌ updateMessage
❌ updateMessages
✅ listMailboxes
❌ moveMessage
❌ moveMessages
❌ deleteMessage - no force option
❌ deleteMessages - no force option
❌ getRawMessage
❌ getQuota - not supported
❌ createMailbox
❌ renameMailbox
❌ deleteMailbox
❌ getAttachment
❌ submitMessage
❌ queueMessage
❌ uploadMessage
❌ subconnections - not supported

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
            result = await this.oAuth2Client.request(accessToken, ...args);
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

    // TODO: caching to avoid traversing
    // TODO: check for changes (added, deleted folders)
    async listMailboxes(options) {
        await this.prepare();

        let specialTags = new Map([
            ['deleteditems', '\\Trash'],
            ['drafts', '\\Drafts'],
            ['inbox', '\\Inbox'],
            ['junkemail', '\\Junk'],
            ['sentitems', '\\Sent']
        ]);

        let specialUseKeys = Array.from(specialTags.keys());
        let specialUseTagIds = new Map();

        let promises = [];
        for (let specialTag of specialUseKeys) {
            let reqUrl = `${OUTLOOK_API_BASE}/me/mailFolders/${specialTag}`;
            promises.push(this.request(reqUrl));
        }
        let resolveResults = await Promise.allSettled(promises);

        for (let resolveResult of resolveResults) {
            let specialUseKey = specialUseKeys.shift();

            if (resolveResult.status === 'fulfilled' && resolveResult.value) {
                specialUseTagIds.set(resolveResult.value?.id, specialTags.get(specialUseKey));
            }
        }

        let result = [];

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

            result.push(...list);

            for (let entry of list) {
                // do not traverse subfolders for folders with a slash in the name
                if (entry.childFolderCount && entry.displayName.indexOf('/') < 0) {
                    await traverse(entry.pathName, entry.id);
                }
            }
        };

        await traverse();

        // keep only real folders and folders that do not contain slash in the name
        result = result.filter(
            entry => (!entry['@odata.type'] || /^#?microsoft\.graph\.mailFolder$/.test(entry['@odata.type'])) && entry.displayName.indexOf('/') < 0
        );

        let mailboxes = result
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

    async listMessages(/*query, options*/) {
        throw new Error('Future feature');
    }
    async getRawMessage(/*messageId*/) {
        throw new Error('Future feature');
    }
    async deleteMessage(/*messageId, force*/) {
        throw new Error('Future feature');
    }
    async deleteMessages(/*path, search*/) {
        throw new Error('Future feature');
    }
    async updateMessage(/*messageId, updates*/) {
        throw new Error('Future feature');
    }
    async updateMessages(/*path, search, updates*/) {
        throw new Error('Future feature');
    }
    async moveMessage(/*messageId, target*/) {
        throw new Error('Future feature');
    }
    async moveMessages(/*source, search, target*/) {
        throw new Error('Future feature');
    }
    async getAttachment(/*attachmentId*/) {
        throw new Error('Future feature');
    }
    async getMessage(/*messageId, options*/) {
        throw new Error('Future feature');
    }
    async getText(/*textId, options*/) {
        throw new Error('Future feature');
    }
    async uploadMessage(/*data*/) {
        throw new Error('Future feature');
    }
    async submitMessage(/*data*/) {
        throw new Error('Future feature');
    }
    async createMailbox(/*path*/) {
        throw new Error('Future feature');
    }
    async renameMailbox(/*path, newPath*/) {
        throw new Error('Future feature');
    }
    async deleteMailbox(/*path*/) {
        throw new Error('Future feature');
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
}

module.exports = { OutlookClient };
