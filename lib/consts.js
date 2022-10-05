'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config(); // eslint-disable-line global-require
    process.env.EE_ENV_LOADED = 'true';
}

module.exports = {
    MESSAGE_NEW_NOTIFY: 'messageNew',
    MESSAGE_NEW_DESCRIPTION: 'New Email – A new email is found from a folder (new email)',

    MESSAGE_DELETED_NOTIFY: 'messageDeleted',
    MESSAGE_DELETED_DESCRIPTION: 'Deleted Message – A previously present email is not found from a folder (deleted email)',

    MESSAGE_UPDATED_NOTIFY: 'messageUpdated',
    MESSAGE_UPDATED_DESCRIPTION: 'Flag Change – Email flags are changed (flag change)',

    MESSAGE_MISSING_NOTIFY: 'messageMissing',
    MESSAGE_MISSING_DESCRIPTION: 'Missing Message – A message that should exist, was not found. Indicates syncing errors.',

    EMAIL_SENT_NOTIFY: 'messageSent',
    EMAIL_SENT_DESCRIPTION: 'Message Accepted – Queued email is accepted by the MTA server (message accepted)',

    EMAIL_DELIVERY_ERROR_NOTIFY: 'messageDeliveryError',
    EMAIL_DELIVERY_ERROR_DESCRIPTION: 'SMTP error – EmailEngine failed to send an email to the SMTP server. This action might be retried. (SMTP error)',

    EMAIL_FAILED_NOTIFY: 'messageFailed',
    EMAIL_FAILED_DESCRIPTION: 'Message Bounced – EmailEngine fails to deliver a queued email to the MTA server (message bounced)',

    EMAIL_BOUNCE_NOTIFY: 'messageBounce',
    EMAIL_BOUNCE_DESCRIPTION: 'Bounce Received – Bounce response email is received (bounce received)',

    EMAIL_COMPLAINT_NOTIFY: 'messageComplaint',
    EMAIL_COMPLAINT_DESCRIPTION: 'Complaint received – FBL complaint was detected',

    MAILBOX_RESET_NOTIFY: 'mailboxReset',
    MAILBOX_RESET_DESCRIPTION: 'Mailbox Reset – UIDValidity for a folder changes (mailbox reset)',

    MAILBOX_DELETED_NOTIFY: 'mailboxDeleted',
    MAILBOX_DELETED_DESCRIPTION: 'Folder Deleted – A previously present folder is not found (folder deleted)',

    MAILBOX_NEW_NOTIFY: 'mailboxNew',
    MAILBOX_NEW_DESCRIPTION: 'New Folder – A new folder is found (new folder)',

    AUTH_ERROR_NOTIFY: 'authenticationError',
    AUTH_ERROR_DESCRIPTION: 'Authentication Failure – EmailEngine fails to authenticate an email account',

    AUTH_SUCCESS_NOTIFY: 'authenticationSuccess',
    AUTH_SUCCESS_DESCRIPTION: 'Authentication Success – An email account is successfully authenticated',

    CONNECT_ERROR_NOTIFY: 'connectError',
    CONNECT_ERROR_DESCRIPTION: 'Connection Failure – EmailEngine fails to establish a connection to an email server',

    ACCOUNT_ADDED_NOTIFY: 'accountAdded',
    ACCOUNT_ADDED_DESCRIPTION: 'Account added – a new email account was registered with EmailEngine',

    ACCOUNT_INITIALIZED_NOTIFY: 'accountInitialized',
    ACCOUNT_INITIALIZED_DESCRIPTION: 'Account initialized – Account has been connected and the first sync is completed',

    ACCOUNT_DELETED_NOTIFY: 'accountDeleted',
    ACCOUNT_DELETED_DESCRIPTION: 'Account deleted – an email account was removed from EmailEngine',

    TRACK_OPEN_NOTIFY: 'trackOpen',
    TRACK_OPEN_DESCRIPTION: 'Email open tracked – recipient opened an email',

    TRACK_CLICK_NOTIFY: 'trackClick',
    TRACK_CLICK_DESCRIPTION: 'Link click tracked – recipient clicked on a link',

    ACCOUNT_DELETED: 'accountDeleted',

    MAX_DAYS_STATS: 7,

    DEFAULT_MAX_LOG_LINES: 10000,

    PDKDF2_ITERATIONS: 25000,
    PDKDF2_SALT_SIZE: 16,
    PDKDF2_DIGEST: 'sha256', // 'sha512', 'sha256' or 'sha1'

    LOGIN_PERIOD_TTL: 30 * 24 * 3600 * 1000,

    DEFAULT_PAGE_SIZE: 20,

    REDIS_PREFIX: ((process.env.EENGINE_REDIS_PREFIX || '').toString().trim() + ':').replace(/^:/, ''),

    REDIS_BATCH_DELETE_SIZE: 1000,

    // start renewing TLS if the certificate expires in 30 days
    RENEW_TLS_AFTER: 30 * 24 * 3600 * 1000,

    // do not attempt certificate renewal more often than once in 8 hours
    BLOCK_TLS_RENEW: 8 * 3600 * 1000,

    // check if we need to renew the certificate once in an hour
    TLS_RENEW_CHECK_INTERVAL: 1 * 3600 * 1000,

    // default download chunk size 1MB
    DEFAULT_DOWNLOAD_CHUNK_SIZE: 1000000,

    // Default value for the CORS Access-Control-Max-Age header
    DEFAULT_CORS_MAX_AGE: 60,

    generateWebhookTable() {
        let entries = [];

        for (let key of Object.keys(module.exports)) {
            if (/_NOTIFY$/.test(key)) {
                let eventData = {
                    key: module.exports[key],
                    description: module.exports[key.replace(/_NOTIFY$/, '_DESCRIPTION')]
                };
                entries.push(eventData);
            }
        }

        let rows = [['Type', 'Name', 'Description']];

        for (let entry of entries) {
            let splitter = entry.description.indexOf('–');
            rows.push([`[${entry.key}](#${entry.key})`, entry.description.substr(0, splitter).trim(), entry.description.substr(splitter + 1).trim()]);
        }

        let colLengths = [0, 0, 0];
        for (let row of rows) {
            for (let i = 0; i < row.length; i++) {
                if (row[i].length > colLengths[i]) {
                    colLengths[i] = row[i].length;
                }
            }
        }

        for (let i = 0; i < rows.length; i++) {
            let row = rows[i];
            console.log(`|${row.map((val, j) => ' ' + val + ' '.repeat(colLengths[j] - val.length + 2)).join('|')}|`);
            if (i === 0) {
                console.log(`|${row.map((val, j) => '-'.repeat(colLengths[j] + 3)).join('|')}|`);
            }
        }
    }
};
