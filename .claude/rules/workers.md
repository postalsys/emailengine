---
description: Worker-thread behavior, failure contracts and known traps for the sync, delivery, webhook, export, SMTP and IMAP-proxy workers.
paths:
  - "workers/**"
  - "lib/email-client/**"
  - "lib/webhooks.js"
  - "lib/export.js"
  - "lib/outbox.js"
  - "lib/imapproxy/**"
  - "lib/delivery-error.js"
  - "lib/worker-rpc-error.js"
  - "lib/account.js"
---

# Workers

EmailEngine runs its sync, delivery, webhook, export, SMTP and IMAP-proxy work in Node.js worker threads (`workers/*.js`), coordinated by `server.js` over message passing. The sections below cover behavior and failure contracts that reading the code alone will not tell you.

## API Worker

The API worker (`workers/api.js`) runs a Hapi.js HTTP server serving both the REST API (`/v1/*`) and admin web UI (`/admin/*`).

**Authentication:**
- **API tokens**: Bearer token via `Authorization` header or `?access_token=` query param
- **Sessions**: Cookie-based (`ee` cookie) for admin UI
- **SSO (admin login)**: Two independent, env-var-only OAuth2/OIDC paths, both via `@hapi/bell`:
  - **Okta** (`OKTA_OAUTH2_*`) - legacy, uses bell's built-in `okta` provider.
  - **Generic OIDC** (`OIDC_*`) - Keycloak, Authentik, Azure AD/Entra, Google, etc. Endpoints come from the issuer's discovery document (`<issuer>/.well-known/openid-configuration`), fetched once at API-worker startup; if discovery fails the SSO button is hidden and password/passkey login still work (no crash). Access control (after authentication) is optional and OR-ed: `OIDC_ALLOWED_USERS` (comma-separated emails and/or `@domain` entries) and/or `OIDC_ALLOWED_GROUPS` (comma-separated group names, matched against the `OIDC_GROUPS_CLAIM` userinfo claim - default `groups`, may be a dotted path like `realm_access.roles`). Both empty means anyone the IdP authenticates; groups require the IdP to emit the claim in userinfo (e.g. a Keycloak Group Membership mapper). `OIDC_FORCED=true` skips the local login screen (auto-redirect to the provider) and disables local password/passkey sign-in - with a fallback to the local form if discovery fails at startup, so an IdP outage can't hard-lock the admin. `OIDC_LOGOUT=true` performs RP-initiated logout (ends the IdP session via `end_session_endpoint`); it works with no IdP config (the IdP shows its own logged-out page) unless `OIDC_POST_LOGOUT_REDIRECT_URI` is set to a registered return-to-app URL. Config and helpers live in `lib/sso.js`; callback route `/admin/login/oidc`. SSO sessions bypass TOTP and cannot manage local password/passkeys (same as Okta).
- **TOTP**: Optional two-factor authentication for admin login

**Running without an admin password is a supported configuration, not a first-run gap.** `server.auth.default('session')` in `workers/api.js` is applied conditionally on `authData`, so while no admin password is set the whole `/admin` surface is reachable with no credential. That is deliberate - the UI renders a dismissible "Authentication not enabled" banner for it. **Do not propose gating admin routes on `authData`**; it was tried for the Bull Board queue browser and reverted in 14590b86, because no session cookie can be minted in that state, so the gate made the page permanently unreachable rather than protected.

The one exception is minting API tokens: a token is never invalidated once issued, so a token handed to a caller that reached the mint route without authenticating keeps working afterwards. The gate keys on the actual request principal, NOT on the global secured-state (`settings.isInstanceSecured()`) - because that global can diverge from what a given API worker actually enforces: `server.auth.default('session')` is applied only in the API worker that observes the password being set, so the CLI `emailengine password` path and sibling API workers do not enforce a session until restart even though `authData` is already in Redis. Each route keys on its own auth strategy's credential shape:
- `POST /admin/tokens/new` (session strategy) - refused unless `request.auth.isAuthenticated`, i.e. the request carries an authenticated admin session. When the conditional session default is not in force on this worker the route is reachable with no session, and `isAuthenticated` is false, so the mint is refused.
- `POST /v1/tokens` (api-token strategy) - refused for the `preauth` caller that the `disableTokens` setting lets through with no credential (the strategy marks it `credentials.preauth = true`). A caller presenting a real API token is trusted, because minting tokens with no admin password set is a supported headless flow (`EENGINE_PREPARED_TOKEN`).

The two conditions are deliberately not unified: the api-token strategy reports the `preauth` bypass as authenticated, so `!isAuthenticated` would wrongly pass it, while the session route never carries a `preauth` marker. `tokens.provision()` itself stays unguarded - gating it there refused the headless CLI flow too.

## IMAP Worker

The IMAP worker (`workers/imap.js`) manages all email account connections and synchronization. Each worker handles multiple accounts via the `ConnectionHandler` class.

**Connection types:**
- **IMAP**: Native IMAP via ImapFlow library with IDLE for real-time sync
- **Gmail API**: OAuth2-based, uses Pub/Sub for notifications (10-min polling fallback)
- **Outlook API**: Microsoft Graph with subscription webhooks (3-day auto-renewal)

**Synchronization:**
- IMAP: Persistent IDLE connection for real-time change detection
- Full mailbox sync on connect, then 15-minute periodic resync
- UID tracking with UIDValidity validation (full resync if changed)
- Exponential backoff reconnection (2s initial, 30s max)

**Error handling:**
- Auth failures tracked; auto-disable ("park") after threshold (3-day window, `EENGINE_MAX_IMAP_AUTH_FAILURE_TIME`). Since 2.79.3 this covers OAuth2 accounts too: the park writes `imap.disabled` (synthesizing a bare `{disabled: true}` blob for an account with no IMAP configuration) plus the provenance marker `AUTH_FAILURE_DISABLED_FIELD`, because the flag is also the operator's send-only switch and every recovery surface (`authFailureDisabledAt`, the page alert, "Resume syncing", the reconnect refusal, the lift that re-authorization performs) is keyed on the marker. The Gmail API and Graph clients check the flag in `init()` via `BaseClient.isSyncDisabled()` before any token work. Known limits, accepted rather than fixed: an app-level token-endpoint failure (expired client secret) that outlasts the window parks every account of that app one by one, and the only way back is per-account re-authorization or "Resume syncing"; the API clients never retry a failed `init()`, so the wall-clock window counts isolated failures at restarts rather than a retry loop. A delegated account (Outlook shared mailbox) is never parked - its failures are the credential owner's. Legacy parks (before the marker existed) are recognised for display by `isAuthFailureDisabled()` through the frozen `AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION`; the OAuth2 ones are stamped with a marker by the one-time startup backfill in `lib/account/auth-failure-backfill.js`
- Transient errors (timeout, DNS) trigger reconnection with backoff
- Permanent errors (5xx) fail immediately
- Dropped-connection reconnects are throttled by connection age (`validateConnectionAge`/`scheduleReconnect`, consulted by BOTH the error and the close handler): a connection that survived `STABLE_CONNECTION_TIME` (5 min) is validated (close path reconnects immediately, error path keeps its debounced error backoff), a shorter-lived one is rescheduled through `closeReconnectBackoff` - a growing jittered delay deliberately NOT reset by a completed setup, only by proven survival. A server that accepts the full setup and then drops the connection used to loop at ~17 logins/sec because every cycle reset the sync-gated backoffs
- Phantom folders (listed without `\Noselect` but rejecting SELECT, e.g. Dovecot shared namespace roots) are skipped per sync pass; after `PHANTOM_SELECT_FAIL_THRESHOLD` consecutive failures the folder is parked like `\Noselect` (`phantomState` marker in the mailbox hash) and re-probed only after `PHANTOM_REPROBE_INTERVAL` or when its STATUS counters change - on some servers the failed SELECT poisons the session, which then gets killed and tears the whole account connection down each cycle

**Limitations:**
- Gmail/Outlook: `getQuota` not supported
- Gmail: No IDLE equivalent (polling fallback)
- Outlook: `uploadMessage` only works for drafts

## Webhooks

The webhooks system (`workers/webhooks.js`, `lib/webhooks.js`) delivers real-time HTTP POST notifications when email events occur. Uses BullMQ queue for reliable delivery with retries.

**Configuration levels:**
1. Global: `webhooksEnabled`, `webhooks` (URL), `webhookEvents` (whitelist)
2. Per-account: `webhooks` URL overrides global
3. Custom routes: Multiple URLs with JavaScript filter/transform functions

**Delivery details:**
- Retries: 10 attempts with exponential backoff (starting at 5s). Each attempt is exactly one HTTP request: the dispatcher deliveries go through (`httpAgent.webhook`, built in `lib/tools.js`) is deliberately a plain `Agent`, not a `RetryAgent`, so a dropped socket or a 429 fails the attempt and the queue's backoff spaces the retries. The shared `httpAgent.retry` retries POSTs on its own and would silently repeat an event with the same `X-EE-Wh-Id` and `X-EE-Wh-Attempts-Made: 0`, unseen by the worker's logs and metrics. Do not point deliveries back at it
- Which failures retry: every non-2xx response goes through the full schedule, 4xx included. This is deliberate - a receiver that is temporarily misconfigured (credentials rotated, a path not deployed yet, a 401/403/404 from an auth proxy in front of it) recovers within the ten attempts, and the reason reaches the operator through `webhookErrorFlag` after the first failure either way. Only `EEGRESSBLOCKED` (egress policy refusal) and `EREDIRECTNOTFOLLOWED` (a 3xx answer) end the job early, because neither can change between attempts. Do not add status codes to that final set without an operator-facing reason: failing fast on 401/403/410/413/422 changes a delivery contract operators rely on
- Authentication: Basic auth via URL credentials (`splitUrlCredentials()` in `lib/tools.js` decodes the percent-encoded userinfo and strips it from the URL), custom headers, or HMAC-SHA256 signature
- Signature header: `X-EE-Wh-Signature` (HMAC-SHA256 of body using service secret)
- Concurrency: Configurable via `EENGINE_NOTIFY_QC` (default: 1)
- Timeout: each delivery attempt is capped at 30s wall-clock (`EENGINE_WEBHOOK_TIMEOUT` to override); a timed-out attempt fails with `ETIMEDOUT` and retries like any other transient error

**Custom routes** (`lib/webhooks.js`):
- `fn` - JavaScript filter function returning boolean (include/exclude event)
- `map` - JavaScript transform function to modify payload before delivery
- Functions run via the SubScript wrapper (Node `vm`) with a 30s synchronous-execution timeout and a 1MB code-size cap. This is NOT a security sandbox - `vm` is not a security boundary, so scripts execute with full server privileges (they can reach `process`, host modules, and secrets). Only trusted operators may author `fn`/`map`/pre-processing scripts; never expose script authoring to untrusted users. Real isolation (isolated-vm / out-of-process) is a tracked follow-up.

## Submit Worker

The submit worker (`workers/submit.js`) processes queued outbound emails via BullMQ and delivers them through SMTP or provider APIs (Gmail, Outlook). All email sending in EmailEngine is asynchronous.

**Retry logic:**
- Default: 10 attempts (`deliveryAttempts` setting)
- Backoff: Exponential starting at 5s (`5s, 10s, 20s, 40s...`)
- Retries on transient errors (< 500 status code)
- No retry on permanent 5xx errors (message rejected). "Permanent" is decided in `lib/delivery-error.js` by PROVENANCE, not by `statusCode`: only a real SMTP reply carries nodemailer's `responseCode`, and when that field is present it decides on its own (5xx permanent except 503; 4xx transient). `statusCode` is a copy made for the API and webhook payloads, and everywhere else in the codebase a 5xx `statusCode` means the opposite of a rejected message (503 "no active handler", 504 RPC timeouts, 500 Redis lock failures, and every API transport's passthrough of the provider's HTTP status) - reading it as an SMTP verdict silently discarded good mail (a 504 RPC timeout during send dropped the queued message outright). Do not "fix" a discarded-message report by adding an error code to an allowlist; make sure the throw site is not forging an SMTP reply code.

  The reply code is consulted BEFORE `NON_RETRYABLE_CODES` on purpose: nodemailer tags envelope/message/auth rejections with `EENVELOPE`/`EMESSAGE`/`EAUTH` regardless of the reply class, so a transient 4xx (e.g. a "450 greylisted" RCPT TO) would otherwise be discarded on the first attempt as if it were a hard rejection. The code allowlist is only the fallback for failures that carry no server reply at all (missing credentials, TLS/protocol mismatch).

  **RPC envelope:** `submitMessage()` runs in the IMAP worker and the error reaches the submit worker through two `postMessage` hops (`workers/imap.js` -> `server.js` -> `workers/submit.js`). Those hops serialize an explicit field list via `lib/worker-rpc-error.js` (`packRpcError`/`unpackRpcError`); `responseCode` is on that list so the SMTP-reply branch actually classifies in production. Any field the predicate depends on must be added there, and delivery-classification tests should round-trip through those helpers (see `test/worker-not-available-test.js`) rather than asserting against the pure predicate. A provider rejection that is genuinely permanent without being an SMTP reply (e.g. Outlook/Graph 400 "Invalid message format") is still retried to exhaustion - if that ever needs discarding, set `responseCode` at the throw site (it now survives) rather than reviving a stripped marker.

**Post-delivery actions:**
- Uploads to Sent folder (if IMAP account, not Gmail)
- Sets `\Answered` flag on replied messages
- Sets `$Forwarded` flag on forwarded messages
- Updates gateway delivery stats (if using gateway)

## Export Worker

The export worker (`workers/export.js`) processes bulk email export jobs via BullMQ. It extracts messages from accounts and writes them to compressed NDJSON files with optional encryption.

**Error handling and recovery:**
- **Transient errors** (network timeouts, 5xx responses): Retry with exponential backoff
- **Skippable errors** (message not found, 404): Skip message, increment counter
- **Account validation**: Checks every 60s if account still exists
**Retry configuration:**
- IMAP messages: 3 retries with 2s base delay (exponential backoff)
- API batch requests: 5 retries for rate limits (429) with 5s base delay
- Folder indexing: 3 retries with 1s base delay

## SMTP Server

The SMTP server (`workers/smtp.js`) is a built-in Message Submission Agent (MSA) that allows legacy applications to send emails through EmailEngine using standard SMTP protocol. Messages are queued for asynchronous delivery via the Submit worker.

**Authentication methods:**
- With auth enabled (`smtpServerAuthEnabled`):
  - Username: Account ID
  - Password: Global password (`smtpServerPassword`) or 64-char hex token with `smtp` scope
- Without auth: Specify account via `X-EE-Account` header in message

**Special headers** (removed before sending):
- `X-EE-Account` - Specify sending account (when auth disabled)
- `X-EE-Idempotency-Key` - Prevent duplicate submissions

**Limitations:**
- Max message size: 25MB (configurable via `EENGINE_MAX_SMTP_MESSAGE_SIZE`)
- Asynchronous delivery only (messages queued, not sent immediately)
- Account must have valid SMTP or OAuth2 credentials configured

## IMAP Proxy

The IMAP proxy (`lib/imapproxy/`) allows standard IMAP clients to access EmailEngine-managed accounts. It abstracts OAuth2 complexity, enabling legacy clients to connect to Gmail, Microsoft 365, and other OAuth2-only providers.

**Authentication methods:**
- Global password: Configure `imapProxyServerPassword` setting
- Access tokens: 64-character hex token with `imap-proxy` or `*` scope

**Limitations:**
- Does not work with API-only accounts (e.g., Mail.ru API mode)
- Requires IMAP support on the email provider
