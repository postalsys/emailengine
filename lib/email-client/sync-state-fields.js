'use strict';

// The fields of the account hash the Gmail API and Graph clients write for themselves. Kept in one
// leaf module (the clients require lib/account.js, so it can not import them) so a flush clears
// every field that holds a client's position in the mailbox: the list used to live in the Account
// model, where a field a client added later would not have been cleared, which is exactly how a
// flush came to leave a Gmail account on its old history ID. test/sync-state-fields-test.js fails
// when a client writes a field listed in neither group.

// Where the client is in the mailbox; a flush clears these and the client starts over from now
const SYNC_STATE_FIELDS = {
    gmail: ['googleHistoryId', 'googleHistoryProcessing'],
    outlook: ['outlookAnnouncedInSince', 'outlookRecoveredUntil']
};

// Written by the clients too, but not a position in the mailbox, so a flush keeps them
const OTHER_CLIENT_FIELDS = ['outlookSubscription', 'outlookLastNotification', 'outlookMailFoldersDeltaUrl'];

module.exports = { SYNC_STATE_FIELDS, OTHER_CLIENT_FIELDS };
