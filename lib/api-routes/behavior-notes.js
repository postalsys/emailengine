'use strict';

// Per-operation behavior notes: the things a caller has to know that the request and
// response schemas cannot express - whether the work is asynchronous, what a 200 actually
// promises, and where a provider's API behaves differently from IMAP.
//
// Routes declare each note TWICE, on purpose:
//   - appended to the route's `notes` array, which hapi-swagger joins into the standard
//     `description` field, so every consumer of /swagger.json sees it;
//   - listed under `plugins['hapi-swagger']['x-ee-behavior']`, so the API reference can tell
//     these apart from the operation's own prose and render them as a callout.
// A vendor extension alone would be invisible to Postman, Redoc and code generators, which
// is exactly the audience that would otherwise ship "a 2xx means sent". A test asserts the
// two declarations stay in step.
//
// The provider notes are transcribed by hand from the transports, and nothing enforces the
// copy. When changing one, check the code that actually implements the limit - not the
// ASCII capability matrices at the top of those files, which are comments too:
//   NO_LABEL_SET_ON_GMAIL     lib/email-client/gmail-client.js, prepareLabelUpdate throw
//   GMAIL_DELETE_IS_TRASH     lib/email-client/gmail-client.js, deleteMessage
//   UPLOAD_DRAFTS_ONLY_GRAPH  lib/email-client/outlook-client.js, uploadMessage
//   NO_QUOTA_ON_API_ACCOUNTS  getQuota on both clients

module.exports = {
    // --- asynchronous work -------------------------------------------------------------
    QUEUED_DELIVERY:
        'Delivery is asynchronous. A 2xx means the message was queued, not that it was sent. Failed attempts are retried with exponential backoff up to the configured deliveryAttempts; follow the outcome through the Outbox endpoints or the messageSent, messageDeliveryError and messageFailed webhooks.',

    SENT_FOLDER_UPLOAD:
        'For SMTP accounts EmailEngine uploads the sent message to the Sent Mail folder after delivery. Gmail API and MS Graph accounts file sent messages themselves, so no upload is performed.',

    SCHEDULED_ON_WORKER:
        'The request only schedules the work and returns before it finishes. Watch the account state, or the accountInitialized and authenticationError webhooks, for the result.',

    BACKGROUND_JOB: 'Runs as a background job. Follow it either by polling the status endpoint or by waiting for the completion webhook.',

    CREDENTIALS_VERIFIED_LATER:
        'Credentials are not verified while handling this request. The account connects afterwards, and an authentication failure surfaces as an authenticationError state rather than an error here. Use the account verification endpoint to test credentials up front.',

    SSE_STREAM: 'A long-lived Server-Sent Events stream rather than a normal request and response. The connection stays open until the client closes it.',

    // --- provider differences ----------------------------------------------------------
    NO_QUOTA_ON_API_ACCOUNTS: 'Quota reporting is not available for Gmail API or MS Graph accounts; the quota field is omitted for those.',

    UPLOAD_DRAFTS_ONLY_GRAPH: 'For MS Graph accounts only drafts can be uploaded, and the draft flag cannot be changed afterwards.',

    NO_LABEL_SET_ON_GMAIL:
        'For Gmail API accounts the entire label set cannot be replaced in one call. Add and remove labels individually instead of using the set operation.',

    GMAIL_DELETE_IS_TRASH:
        'For Gmail API accounts the message is always moved to Trash. The force option, which permanently deletes on IMAP accounts, has no effect.',

    IMAP_ONLY: 'Only available for IMAP accounts. Gmail API and MS Graph accounts have no equivalent.'
};
