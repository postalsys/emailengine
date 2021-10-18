'use strict';

module.exports = {
    MESSAGE_NEW_NOTIFY: 'messageNew',
    MESSAGE_NEW_DESCRIPTION: 'A new email is found from a folder',

    MESSAGE_DELETED_NOTIFY: 'messageDeleted',
    MESSAGE_DELETED_DESCRIPTION: 'A previously present email is not found from a folder',

    MESSAGE_UPDATED_NOTIFY: 'messageUpdated',
    MESSAGE_UPDATED_DESCRIPTION: 'Email flags are changed',

    EMAIL_SENT_NOTIFY: 'messageSent',
    EMAIL_SENT_DESCRIPTION: 'Queued email is accepted by the MTA server',

    EMAIL_FAILED_NOTIFY: 'messageFailed',
    EMAIL_FAILED_DESCRIPTION: 'EmailEngine fails to deliver a queued email to the MTA server',

    EMAIL_BOUNCE_NOTIFY: 'messageBounce',
    EMAIL_BOUNCE_DESCRIPTION: 'Bounce response email is received',

    MAILBOX_RESET_NOTIFY: 'mailboxReset',
    MAILBOX_RESET_DESCRIPTION: 'UIDValidity for a folder changes',

    MAILBOX_DELETED_NOTIFY: 'mailboxDeleted',
    MAILBOX_DELETED_DESCRIPTION: 'A previously present folder is not found',

    MAILBOX_NEW_NOTIFY: 'mailboxNew',
    MAILBOX_NEW_DESCRIPTION: 'A new folder is found',

    AUTH_ERROR_NOTIFY: 'authenticationError',
    AUTH_ERROR_DESCRIPTION: 'Authentication fails for an email account',

    AUTH_SUCCESS_NOTIFY: 'authenticationSuccess',
    AUTH_SUCCESS_DESCRIPTION: 'An email account is successfully authenticated',

    CONNECT_ERROR_NOTIFY: 'connectError',
    CONNECT_ERROR_DESCRIPTION: 'EmailEngine fails to establish a connection to an email server',

    MAX_DAYS_STATS: 7
};
