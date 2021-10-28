'use strict';

module.exports = {
    MESSAGE_NEW_NOTIFY: 'messageNew',
    MESSAGE_NEW_DESCRIPTION: 'New Email – A new email is found from a folder (new email)',

    MESSAGE_DELETED_NOTIFY: 'messageDeleted',
    MESSAGE_DELETED_DESCRIPTION: 'Deleted Message – A previously present email is not found from a folder (deleted email)',

    MESSAGE_UPDATED_NOTIFY: 'messageUpdated',
    MESSAGE_UPDATED_DESCRIPTION: 'Flag Change – Email flags are changed (flag change)',

    EMAIL_SENT_NOTIFY: 'messageSent',
    EMAIL_SENT_DESCRIPTION: 'Message Accepted — Queued email is accepted by the MTA server (message accepted)',

    EMAIL_FAILED_NOTIFY: 'messageFailed',
    EMAIL_FAILED_DESCRIPTION: 'Message Bounced – EmailEngine fails to deliver a queued email to the MTA server (message bounced)',

    EMAIL_BOUNCE_NOTIFY: 'messageBounce',
    EMAIL_BOUNCE_DESCRIPTION: 'Bounce Received – Bounce response email is received (bounce received)',

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

    MAX_DAYS_STATS: 7,

    DEFAULT_MAX_LOG_LINES: 10000
};
