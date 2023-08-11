'use strict';

const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const logger = require('../logger');

const SKIP_LABELS = ['UNREAD', 'STARRED', 'IMPORTANT', 'CHAT', 'CATEGORY_PERSONAL'];

const SYSTEM_LABELS = {
    SENT: '\\Sent',
    INBOX: '\\Inbox',
    TRASH: '\\Trash',
    DRAFT: '\\Drafts',
    SPAM: '\\Junk'
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

class GmailClient {
    constructor(account, options) {
        this.account = account;
        this.options = options || {};
        this.redis = options.redis;
        this.logger = options.logger || logger;
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

    async listMailboxes(query) {
        await this.prepare();

        const accessToken = await this.getToken();

        let labelsResult = await this.oAuth2Client.request(accessToken, 'https://gmail.googleapis.com/gmail/v1/users/me/labels');
        let labels = labelsResult.labels.filter(label => !SKIP_LABELS.includes(label.id));

        let resultLabels;
        if (query && query.counters) {
            resultLabels = [];
            for (let label of labels) {
                let labelResult = await this.oAuth2Client.request(accessToken, `https://gmail.googleapis.com/gmail/v1/users/me/labels/${label.id}`);
                resultLabels.push(labelResult);
            }
        } else {
            resultLabels = labels;
        }

        resultLabels = resultLabels
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

                if (label.type === 'system' && SYSTEM_LABELS[label.id]) {
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

        return { mailboxes: resultLabels };
    }
}

module.exports = { GmailClient };

const { redis } = require('../db');

let gmailClient = new GmailClient('api', { redis });
gmailClient
    .listMailboxes()
    .then(r => console.log(r))
    .catch(err => console.error(err))
    .finally(() => process.exit());
