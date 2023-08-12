'use strict';

const { Account } = require('../account');
const { oauth2Apps } = require('../oauth2-apps');
const getSecret = require('../get-secret');
const logger = require('../logger');
const util = require('util');
const addressparser = require('nodemailer/lib/addressparser');

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

        return { mailboxes: resultLabels };
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

    formatMessage(messageData, options) {
        let { extended, path } = options || {};

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
        for (let label of messageData.labelIds) {
            if (SYSTEM_LABELS.hasOwnProperty(label)) {
                labels.push(SYSTEM_LABELS[label]);
            } else {
                labels.push(label);
            }
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

        let result = {
            id: messageData.id,
            uid: messageData.uid,

            path: (extended && path) || undefined,

            emailId: messageData.id || undefined,
            threadId: messageData.threadId || undefined,

            date: date ? date.toISOString() : undefined,

            flags,
            labels,

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

            //TODO:
            //attachments: attachments && attachments.length ? attachments : undefined,
            messageId: (envelope.messageId && envelope.messageId.toString().trim()) || undefined,
            inReplyTo: envelope.inReplyTo || undefined,

            headers: extended ? headers : undefined,
            // TODO:
            text: /*textId
                ? {
                      id: textId,
                      encodedSize: encodedTextSize
                  }
                : */ undefined
        };

        return result;
    }

    async listMessages(query) {
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

            let labelsResult = await this.oAuth2Client.request(accessToken, 'https://gmail.googleapis.com/gmail/v1/users/me/labels');
            let label = labelsResult.labels.find(entry => entry.name === path || entry.id === path);
            if (!label) {
                return false;
            }
            requestQuery.labelIds = label.id;
        }

        let messageList = [];
        let listingResult = await this.oAuth2Client.request(accessToken, 'https://gmail.googleapis.com/gmail/v1/users/me/messages', 'get', requestQuery);
        for (let { id: message } of listingResult.messages) {
            let messageData = await this.oAuth2Client.request(accessToken, `https://gmail.googleapis.com/gmail/v1/users/me/messages/${message}`);
            console.log(util.inspect(messageData, false, 22, true));
            if (messageData) {
                messageList.push(this.formatMessage(messageData, { path }));
            }
        }

        return messageList;
    }
}

module.exports = { GmailClient };

const { redis } = require('../db');

let gmailClient = new GmailClient('api', { redis });
gmailClient
    .listMailboxes()
    .then(r => console.log(r))
    .then(() => gmailClient.listMessages({ path: 'INBOX' }))
    .then(r => console.log(JSON.stringify(r, false, 2)))
    .catch(err => console.error(err))
    .finally(() => process.exit());
