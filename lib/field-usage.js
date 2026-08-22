'use strict';

const { COLLAPSE_CLASS } = require('./consts');

// Long-form guidance for the fields where knowing what a value IS does not tell you when to
// send it. Attached to the joi schemas with `.meta({ usage })`, which the OpenAPI generator
// publishes as `x-meta.usage` - so it reaches /swagger.json and every consumer of it, not
// only the admin API reference.
//
// This is the sibling of lib/enum-descriptions.js and exists for the same reason: prose
// belongs somewhere it can be read and edited as prose, not smeared across schema
// definitions a line at a time.
//
// A note is for a field whose CHOICE is not obvious, never for one whose meaning is not.
// `subject` does not get one. Two questions a description cannot answer are what earn a
// field an entry here:
//
//   when would I reach for this
//   what does sending it do to the other fields
//
// It is also where the long half of an overlong description goes. Seventeen fields used to
// put three or four lines of caveats inline, on a page where the median description is one
// short sentence - so the fields with the most to say were the ones that made the page
// hardest to scan. The description keeps the first sentence, the caveats move here, and the
// API reference renders them behind a closed "When to use this" disclosure. Net result is
// fewer lines on screen, not more.
//
// Format: plain paragraphs, backtick code spans, absolute links. lib/api-reference/format.js
// escapes first and only adds back a closed tag set, so a heading or a list renders as
// literal text - the same constraint the `info.description` in workers/api.js is written
// under. Blank lines separate paragraphs.
//
// Keep them short. Two to four sentences is the target; anything longer belongs in the
// documentation site with a link from here.

const AUTH_USAGE =
    'Send this for ordinary password authentication. Omit it when `useAuthServer` is on, because EmailEngine then fetches credentials from your authentication server for every connection and a stored password would be dead configuration.\n\n' +
    'On an update this replaces the whole credentials object unless `partial` is also set.';

// The collapse marker is part of the output contract, and both web-safe options promise it. Said
// once here so the two published descriptions cannot end up describing it differently.
const COLLAPSE_MARKER_USAGE =
    `Quoted thread history is folded into one collapsed \`<details class="${COLLAPSE_CLASS}">\` element so you can hide it behind a single control. ` +
    'Its `<summary>` is deliberately empty, so supply your own label.';

const FIELD_USAGE = {
    accountId:
        'Set this when your own system already has an identifier for the mailbox, for example a user id, so you can address the account later without storing a second id. Leave it `null` and EmailEngine generates one, which comes back in the response.\n\n' +
        'Reusing an existing id is an update, not an error: the registration endpoint applies the new settings to that account rather than creating a second one.',

    expectedEmail:
        'Set this when the account is created through a hosted authentication form and you already know which mailbox the user is supposed to connect, so a user cannot finish the form against a different account than the one you provisioned.\n\n' +
        'For OAuth2 the address is compared against what the provider reports, never against anything the caller supplied, so for a shared or delegated mailbox this has to be the authenticating principal rather than the mailbox address. For IMAP it is compared against the address typed into the form, which the credentials do not prove ownership of.\n\n' +
        'The constraint stays on the account and is enforced again on every later reauthentication.',

    imapPath:
        'Leave this at `"*"` unless the account is large and you only care about a few folders. Narrowing it reduces the number of folders EmailEngine keeps open and indexes, which is the main cost of syncing a big mailbox.\n\n' +
        'Unmonitored folders stay fully reachable through the API. What you give up is webhooks: nothing is emitted for changes in a folder that is not on this list.',

    // Same note either way: nothing in it is protocol specific, and the two keys stay
    // separate so one can diverge later without touching the other's schema.
    imapAuth: AUTH_USAGE,
    smtpAuth: AUTH_USAGE,

    useAuthServer:
        'Turn this on when passwords must not be stored in EmailEngine, for instance when they are short-lived or held in your own vault. EmailEngine then calls your authentication server for credentials each time it needs to connect, and the `auth` block must be omitted.\n\n' +
        'The authentication server URL itself is an instance-wide setting, not a per-account one.',

    partialUpdate:
        'Set this when you are changing one setting and do not want to resend the rest. Without it the configuration object you send replaces the stored one wholesale, so any key you leave out is cleared.\n\n' +
        'It applies only to the block it sits in: a partial `imap` update alongside a full `smtp` object updates one and replaces the other.',

    disableIMAP4rev2:
        'Set this only after a server has actually misbehaved. A handful of IMAP servers advertise IMAP4rev2 support and then answer incorrectly, and this forces EmailEngine back to IMAP4rev1 for that account.\n\n' +
        'It has no effect on accounts that authenticate with OAuth2.',

    // No description of what `full` and `fast` do: the row lists both values with their own
    // descriptions from lib/enum-descriptions.js a few lines under this note, and saying it
    // twice on one row is what that split exists to avoid.
    imapIndexer:
        'Leave this unset to follow the instance-wide setting, and only override it for accounts whose mailboxes behave differently from the rest of your fleet. A very large mailbox that nothing else writes to is the usual reason.',

    exportFolders:
        'Name folders when you want a subset, by path or by special-use flag such as `\\Sent`. Leaving it empty is not "nothing", it is a documented default: Gmail and Outlook API accounts export All Mail, and every other account exports every folder except Junk and Trash.',

    searchEmailIds:
        'Use this when you already know which messages you want, typically from an earlier search or from a webhook. It is not a filter that narrows the other criteria - when it is present every other search field is ignored.',

    mailboxSubscribed:
        'Only IMAP accounts have a subscription list, so this is ignored for Gmail API and MS Graph accounts. It controls whether a folder shows up in clients that list subscribed folders only; it does not affect whether EmailEngine syncs it, which `path` on the account decides.',

    messageRaw:
        'Send `raw` when you have already built the MIME message yourself, for example when relaying something you fetched from another system, and it has to go out unchanged.\n\n' +
        'Anything else you send alongside it overrides the matching header inside it, so a `subject` sent with a raw body replaces the subject in the message. If you are composing from parts, use `text` and `html` and let EmailEngine build the MIME structure.',

    messageEnvelope:
        'Send this only when the SMTP envelope has to differ from the message headers, which in practice means variable envelope return paths, a bounce address that is not the From address, or delivering to an address that does not appear in the headers.\n\n' +
        'Left out, the envelope is derived from the headers, which is what you want for an ordinary message.',

    mailMerge:
        'Use this to send one personalised message per recipient in a single request, instead of one request each. Each entry gets its own queue id and its own delivery.\n\n' +
        'It takes over addressing and rendering for the whole request: `messageId`, `envelope`, `to`, `cc`, `bcc` and `render` at the message root are rejected, because each entry supplies its own.',

    messageCopy:
        'Leave this unset to follow the account default. Set it explicitly when one message should be filed differently from the rest, for instance an automated notification you do not want in the user Sent folder.\n\n' +
        'It only affects SMTP deliveries. Gmail and MS Graph file sent messages themselves, so the flag is a no-op there.',

    attachmentReference:
        'Use this to forward an attachment that is already on another message without downloading and re-uploading it. Take the id from the attachment list of the referenced message.\n\n' +
        'It is exclusive with `content`: send one or the other, never both.',

    referenceThreadId:
        'Set this when you know the Gmail thread the outgoing message belongs to and do not want EmailEngine to work it out from the referenced message.\n\n' +
        'Gmail API accounts only. IMAP and MS Graph derive threading from the `In-Reply-To` and `References` headers and ignore it. When both `message` and `threadId` are given, this one wins.',

    openAiAPIUrl:
        'Set this only for an OpenAI-compatible service that is not OpenAI itself, and include whatever path prefix that service mounts its API under. For Azure OpenAI that means `https://<your-resource>.openai.azure.com/openai/v1`, not the bare host.',

    revokeGrant:
        'Set this when deleting an account should also cut EmailEngine off at the provider, for example because a user asked for their data to be disconnected rather than just removed here.\n\n' +
        'It currently works for individual Gmail OAuth2 grants. Gmail Workspace service-account integrations, Outlook and non-OAuth2 accounts ignore it. A failed revocation is logged and never blocks the deletion.',

    webSafeHtml:
        'Turn this on when you are rendering the message in your own UI and want EmailEngine to do the sanitising. It is a shorthand that overrides `textType`, `preProcessHtml` and `embedAttachedImages`.\n\n' +
        'Send `embedAttachedImages=false` alongside it when the body is going to be read rather than displayed - see that parameter.\n\n' +
        COLLAPSE_MARKER_USAGE,

    embedAttachedImages:
        'Inlining every referenced attachment as a data URI is what makes a rendering self-contained, and it is also what makes it several times larger. Leave it off for a body that is going to be read rather than displayed.\n\n' +
        'This is the one part of the `webSafeHtml` shorthand you can keep: an explicit `false` alongside it leaves the `cid:` references as they are and the attachments to be fetched separately, without giving up the sanitising or the single HTML rendering.',

    webSafeText:
        'Turn this on when you are rendering the body in your own UI and want EmailEngine to do the sanitising. Both MIME parts are fetched and folded into one sanitised HTML rendering, which is generated from the plaintext part when the message carries no HTML one.\n\n' +
        'The response then carries `html` and no `plain`: the two would be the same message twice. ' +
        COLLAPSE_MARKER_USAGE,

    useOutlookSearch:
        'Turn this on for MS Graph accounts when you need to search fields that the default `$filter` mode cannot reach: `to`, `cc`, `bcc`, `larger`, `smaller`, `body`, `before`, `sentBefore`, `since` and `sentSince`.\n\n' +
        'What you give up is worth checking first. `$search` returns at most 1,000 results, reports neither a total nor a page count, and orders by relevance rather than by date. The `labels` filter is unavailable in this mode, so leave it off when you need to filter by category.',

    useStructuredFormat:
        'Turn this on for MS Graph accounts sending from a shared mailbox, because it is the only mode that respects the `from` address.\n\n' +
        'The cost is fidelity: structured JSON breaks calendar invites and other special MIME types. The default, raw MIME, preserves them but ignores `from`.',

    messagePage:
        'Prefer the paging cursor. This exists for IMAP accounts and for callers written before cursors, and it is ignored entirely when a cursor is also supplied.'
};

module.exports = { FIELD_USAGE };
