# EmailEngine - Feature Map & Prioritized Test Plan

Generated 2026-06-16. Read-only audit across five feature areas (email sync engine, REST API, admin UI, background workers/queues, core libraries). No source or tests were modified.

Baseline: ~70k LOC source (lib + workers + server.js) vs ~16.1k LOC unit tests, ~1.8k integration, 180 e2e.

---

## 1. Feature & functionality map

EmailEngine is a multi-threaded (Worker Threads), Redis-backed email sync platform exposing a REST API + admin UI.

### Email sync engine (lib/email-client/*, workers/imap.js, lib/account*)
- Three providers behind a shared `BaseClient`: IMAP (ImapFlow + IDLE), Gmail API (Pub/Sub + 10-min poll fallback), Outlook/Graph (subscription webhooks, 3-day renewal).
- Message ops: list/get/getText/getRawMessage/getAttachment/update/move/delete/upload (+ bulk variants).
- Mailbox ops: list/create/modify/delete; special-use resolution; provider path encoding (Outlook `/`,`%`; Gmail label<->folder).
- IMAP sync: `determineSyncStrategy` -> none/partial(condstore|simple)/full; UIDValidity change -> full resync + index reseed; lost-index silent reseed; batched fetch with retry/backoff.
- Reliability: exponential reconnect/backoff; auth-failure tracking + auto-disable (`setErrorState`); error classification -> account state (authenticationError vs connectError); state machine (account-state.js).
- Send path: `queueMessage`/`submitMessage` (SMTP + Gmail/Outlook API), idempotency keys, post-delivery Sent-folder upload + Answered/Forwarded flags + gateway stats.

### REST API (lib/api-routes/*, ~8.1k LOC, 20 modules)
- Account + message + mailbox CRUD/ops; submit; outbox; export; gateways; templates; tokens; settings; oauth2-apps; webhook-routes; blocklist; chat (doc-store-gated); delivery-test; license; pubsub; stats; bull-board.
- Single `api-token` bearer strategy: scope derived from route tags (all REST modules use `api`); account-token binding restricts to own `{account}`; IP/referrer allowlist + per-token rate limit; `disableTokens` open-API bypass.

### Admin UI (lib/ui-routes/*, lib/routes-ui.js, workers/api.js; ~128 routes)
- Auth: session cookie (`ee`), TOTP, passkeys/WebAuthn (intentionally bypasses TOTP), OKTA OAuth2, pbkdf2 password, `passwordVersion` force-logout.
- CSRF via @hapi/crumb (skip-list: api/metrics/static/external tags).
- Config screens: webhooks, service, AI, logging/Sentry, license, OAuth apps, network/proxy, SMTP/IMAP-proxy servers, document-store (deprecated, self-gates off).
- Public (auth:false) flows: add-account wizard (HMAC-signed form), OAuth start/redirect (account creation), unsubscribe.

### Background workers & servers (workers/*, server.js, lib/webhooks.js, lib/export.js)
- Submit worker: BullMQ delivery, retry/backoff classification (`NON_RETRYABLE_CODES`, 5xx-not-503 -> discard).
- Webhooks worker: BullMQ delivery (10 attempts, HMAC sig), custom routes with sandboxed `fn`/`map` (SubScript/vm).
- Export worker: phased NDJSON export, gzip + optional AES-256-GCM, recovery, atomic concurrency Lua.
- SMTP server (MSA) + IMAP proxy: three auth modes each (global password / scoped hex token / header or passthrough).
- Documents worker: deprecated Elasticsearch indexing, gated off by default.
- server.js main process: worker spawn/health/restart, account assignment (load-aware round-robin + rendezvous reassignment), RPC with timeout.

### Core libraries (lib/*)
- oauth2-apps.js (OAuth2 app config + token orchestration, 5 providers, WIF, Pub/Sub IAM), oauth/* providers.
- tokens.js (API + session tokens, hashed storage), encrypt.js (AES-256-GCM), settings.js (encrypted keys).
- tools.js (binary sync-state serialize/unserialize, license verify, signed-form HMAC, glob matcher, redaction).
- bounce-detect.js / arf-detect.js (DSN + FBL parsing), add-trackers.js, get-raw-email.js, autodetect-imap-settings.js, rewrite-text-nodes.js, templates.js, redis-operations.js.

---

## 2. Current coverage assessment

Strong (real source imported, good cases):
- IMAP sync-strategy helpers, lost-index recovery, processChanges, null/event guards, mailbox-listing diff, Outlook folder encoding, label search filters, account-state helpers (email sync).
- Gmail Pub/Sub manager recovery, WIF external-account signer, OAuth token-request encoding + scope/nonce/error-status, tokens.js, encrypt.js, stream-encrypt, export.js internals + concurrency Lua, IMAP-proxy protocol hardening, redis-operations helpers, bounce/ARF structured (RFC 3464) parsing.

Thin or absent:
- Entire api-routes/ and ui-routes/ handler execution: exercised only via integration smoke (401-without-token + 200-with-`*`-token) and one e2e happy path. No scoped/cross-tenant token tests, no CSRF assertion, no POST mutation handlers, no parameterized routes.
- Send/submit pipeline, auth auto-disable, reconnect/backoff, Gmail history sync, Outlook subscription lifecycle: only the flaky non-hermetic live integration suite.
- SubScript sandbox, server.js account assignment/reassignment, SMTP/IMAP-proxy auth layers: zero tests.
- Large files barely touched: outlook-client.js (4584), gmail-client.js (3079), base-client.js (3279), imap/mailbox.js (3255), workers/api.js (3185), schemas.js (2497), tools.js (2372, ~27% of exports + all binary/crypto/async untested), oauth2-apps.js handler class, autodetect-imap-settings.js (779, 0 tests), get-raw-email.js (552, 0).

---

## 3. Cross-cutting findings

### 3a. "Illusory coverage" - tests that re-implement source instead of importing it
These pass green even when the shipping code breaks. Highest ROI to fix:
- `worker-not-available-test.js` - copies the submit discard predicate; omits the `NON_RETRYABLE_CODES` (EAUTH/EOAUTH2/ETLS/...) branch entirely.
- `autoreply-test.js` - re-defines `isAutoreply`; real `BaseClient.isAutoreply` (base-client.js:2173) untested.
- `complaint-test.js` - re-implements `mightBeAComplaint`; real wrapper untested (underlying arf-detect IS tested).
- `email-client-test.js` - defines its own PageCursor + constants; real Gmail `PageCursor` untested.
- `retry-logic-test.js` - defines its own `calculateBackoffDelay`/`simulateRequestWithRetry`; real Outlook `requestWithRetry` (outlook-client.js:222) untested.

### 3b. Auth boundaries asserted only at "401 without any token"
Scope enforcement, cross-account binding, CSRF, session invalidation, and the admin auth gate are never positively tested with real (scoped / cross-tenant / crumb-less) requests. The test prepared token decodes to `scopes:["*"]`, so every integration/e2e run is a full-root token.

### 3c. Latent bugs surfaced during the audit (not tests - fix separately)
- arf-detect.js:112 - reads `report['source-ip']` but writes `report.arf['source-ip']` (source IP never populated).
- worker-not-available-test.js silently omits a whole discard branch (see 3a).
- `mightBeABounce`/`mightBeAComplaint`/`mightBeDSNResponse` are duplicated in both base-client.js (2832-2890) and imap/mailbox.js (3056-3204) - drift risk; consolidate.

---

## 4. Prioritized test backlog

Priority = blast radius x regression likelihood x security sensitivity, weighted by cost-to-implement (cheap high-value first).

### P0 - Do first

| # | Test | Why | Type |
|---|------|-----|------|
| 1 | Fix the 5 "illusory coverage" tests to import real exports (submit discard incl. NON_RETRYABLE_CODES, isAutoreply, mightBeAComplaint, Gmail PageCursor, Outlook requestWithRetry) | False green today; cheapest possible win; unblocks trust in the suite | unit |
| 2 | SubScript sandbox (lib/sub-script.js) - timeout enforcement, no process/require/global escape, env/scriptEnv injection, payload isolation, compile-error caching | Arbitrary user JS runs in-process on every webhook; zero tests | unit |
| 3 | tools.serialize / unserialize round-trip - UID+flags+modseq+msgpack, D/N sentinels, BigInt modseq | Corrupts sync state for ALL accounts (dup/dropped messages + webhooks); zero tests; pure/cheap | unit |
| 4 | API token scope enforcement + cross-account binding (workers/api.js:1106,1121-1170) - smtp/imap-proxy-only token must 403 on /v1/*; account token must 403 on a different account; template special-casing | Core security boundaries, tested only at 401-without-token; provision tokens via lib/tokens.provision() in existing smoke harness | integration |
| 5 | Admin UI auth gate + CSRF + passwordVersion - boot server WITH admin password: anonymous /admin/* -> 302 login; crumb-less POST -> 403; passwordVersion bump invalidates old cookie | Closes the 3 highest-blast-radius UI gaps at once; a regression making admin world-readable passes all current tests | integration |

### P1 - High

| # | Test | Why | Type |
|---|------|-----|------|
| 6 | Send/submit pipeline + idempotency (base-client.js submitMessage/queueMessageEntry/handleSubmitError, checkIdempotencyKey) - permanent-5xx vs transient, Sent-folder upload, reference flags, gateway stats | Data loss / duplicate sends; only happy-path live coverage | unit + 1 integration error path |
| 7 | server.js account assignment & reassignment (assignAccounts, rendezvous reassign trigger, call-failure rollback, worker-exit -> unassigned, 10s failsafe, health -> restart) | Highest orchestration blast radius (one routing bug hits all accounts); zero tests | unit (extract) / integration with fake workers |
| 8 | setErrorState auth-failure auto-disable (base-client.js:383) - error-count, same-error dedupe, MAX_IMAP_AUTH_FAILURE_TIME threshold, disable+close | Safety mechanism vs reconnect storms; untested | unit (mock redis txn + clock) |
| 9 | SMTP server + IMAP-proxy AUTH layers (workers/smtp.js:112-246, imapproxy/imap-server.js:153-247) - global password, scoped hex token, account==username, IP restriction, API-only rejection | Auth-bypass surface; protocol hardening is tested but auth is not | integration |
| 10 | Bulk message mutate/delete REST (message-routes.js PUT /messages, /messages/move, /messages/delete?force) | Highest data-loss blast radius among untested endpoints; matches prior Outlook bulk-delete finding | integration |
| 11 | bounce-detect text-heuristic fallback (~13 vendor matchers: Exim/Postfix/Google/KDDI/Verizon/James/generic 5xx, bounce-detect.js:417-832) | Largest real-world regression surface; regex-fragile (ReDoS-hardened, no regression test) | unit (fixtures) |
| 12 | OAuth2AppsHandler stateful core (oauth2-apps.js create/update/del encryption, getServiceAccessToken caching/lock:1641, getClient per-provider:1422) + Gmail/Outlook checkForFlags error->flag mapping | Mis-stored/plaintext creds, token stampede, wrong auth flags; only leaf helpers tested today | unit |
| 13 | Gmail history sync (processHistory/processHistoryEntry, gmail-client.js:2737-3001) + Outlook subscription lifecycle (renewSubscription/ensureSubscription/syncMissedMessages, outlook-client.js:3224-3971) | Core real-time correctness; only flaky live coverage; silent event loss | unit (mock request) |
| 14 | IMAP reconnect/backoff + error->state classification (imap-client.js reconnect:910, start() catch:1557) | Timing-sensitive; high regression likelihood | unit (fake timers) |

### P2 - Medium

| # | Test | Why | Type |
|---|------|-----|------|
| 15 | bull-board auth (/admin/bull-board/* relies only on default session guard) | Queue job payloads (recipients/message data) leak if guard regresses | integration |
| 16 | chat / unified-search REST doc-store gating (/v1/chat 404 + /v1/unified/search runtime-404 when feature off) | doc-store-disabled test covers UI only | route-table + integration |
| 17 | Secret masking on read (GET /v1/account, /v1/oauth2 -> ******) | Assert secrets never round-trip cleartext | integration |
| 18 | Public account-setup HMAC verification (/accounts/new/imap/server, POST /v1/authentication/form) + signed-form replay/TTL/nonce | Unauth account creation + credential write if sig check regresses | integration + unit |
| 19 | settings.js secret encrypt/decrypt + POST /v1/settings write broadcast | Silent corruption of stored OAuth secrets/serviceSecret; global blast radius | unit + integration |
| 20 | Security redaction units: formatPartialSecretKey, add-trackers redirect rewriting (open-redirect via /redirect), get-raw-email X-EE-*/BCC stripping | Header/secret leakage on every outbound message | unit |
| 21 | UIDVALIDITY-change full-resync branch (mailbox.js onOpen:2102-2127) | Distinct from lost-index reseed; wrong handling re-floods or drops messages | unit |
| 22 | Export recovery + encryption end-to-end (markInterruptedAsFailed, gzip->encrypt->decryptable artifact, lease extension) | Classifiers tested in isolation; recovery flow not | integration |
| 23 | Webhook custom-route fn/map filter/transform end-to-end + payload formatting/truncation + route-disable-on-compile-error + HMAC sig value | Handler cache tested; actual filter/transform behavior not | unit/integration |
| 24 | autodetect-imap-settings.js (779 LOC, 0 tests) - provider table, autoconfig XML substitution, escapeXml autodiscover injection, SRV parsing | Every new-account config; high churn; injection surface | unit (stub dns/undici) |
| 25 | smtp-pool-manager generatePoolKey (credential isolation) + cleanupIdlePools | Pool-key collision could cross-send via wrong account | unit |
| 26 | Broad POST mutation + parameterized route execution (token provision/delete, account delete/edit, gateway/oauth/webhook/template CRUD, network config) with a prepared session | ~20 handlers only snapshot-checked, never run | integration / e2e |
| 27 | gateway CRUD + delivery-stats hincrby + encrypted-pass roundtrip | Holds SMTP creds; only route-name smoke today | unit/integration |

### P3 - Lower / opportunistic

- message-builder.js + notification-handler.js builders (synchronous, cheap; payload contract).
- export-routes / outbox / blocklist / template / license HTTP behavior (404 + force semantics + download stream).
- redis-url parsing, redis-scan-delete batching, reconnection-manager backoff cap, rate-limit bucket math, capa CSV parser, templates CRUD.
- arf-detect edge branches (and fix the source-ip read/write bug, 3c).
- OKTA login flow, disableTokens open-API mode, sess_ browse round-trip, requireTotp path-allowlist correctness.
- mergeObjects prototype-pollution guard, comparePattern/matcher glob+LRU, checkLicense ECDSA verify.
- Documents/ES enabled path (deprecated, off by default - lowest priority).

---

## 5. Suggested sequencing

1. Land P0 #1 (illusory-coverage fixes) immediately - cheapest, removes false confidence, and #1's submit/autoreply/complaint cases overlap with P1 #6/#11.
2. P0 #2/#3 (SubScript, serialize) - pure units, high blast radius, no infra needed.
3. P0 #4/#5 + P2 #15/#16/#17/#26 share one new integration harness: boot the test server with an admin password and provision scoped tokens via lib/tokens.provision(). Build that harness once, then the auth/scope/CSRF/masking/gating tests are incremental.
4. P1 #6-#14 are the email-engine correctness core; most are unit-testable with mocked redis/transport/request and benefit from extracting pure logic out of the giant client files as you go.

---

## 6. Implementation status (2026-06-16)

Branch `test-coverage-p0-p1`. Each test file was verified to pass individually
(the full local suite cannot run all files in parallel on a dev machine due to
process-isolation + Redis connection accumulation; CI runs the unit tier in a
clean dedicated job). Source changes are additive exports or behavior-preserving
extractions, verified not to break existing consumers.

Done (committed):
- P0 #1 - illusory-coverage tests now exercise real code (submit discard via new
  lib/delivery-error.js incl. NON_RETRYABLE_CODES; isAutoreply; Mailbox
  mightBeAComplaint + base-client drift; Gmail PageCursor; Outlook
  requestWithRetry incl. transient-network branch).
- P0 #2 - SubScript sandbox (timeout, context isolation, env, compile cache).
- P0 #3 - tools.serialize/unserialize round-trip.
- P0 #4 - API token scope enforcement + cross-account binding (integration).
- P0 #5 - admin CSRF crumb enforcement (integration). [partial]
- P1 #8 - setErrorState auth-failure tracking + IMAP auto-disable.
- P1 #11 - bounce-detect text-heuristic fallback.
- P1 #12 - Gmail/Outlook checkForFlags/checkForUserFlags error mapping. [partial]
- P1 #14 - ReconnectionManager backoff/jitter/reset. [partial]
- P1 #6 - idempotency-key handling (duplicate-submission guard). [partial]

Remaining (deferred, with reason):
- P0 #5 remainder - anonymous /admin/* -> 302 redirect and passwordVersion
  session invalidation need an isolated server WITH an admin password; belongs
  in the Playwright e2e suite (cannot verify locally without Chromium + the
  external trial endpoint). The shared integration server is password-less by
  design, so these must not mutate its global auth state.
- P1 #6 remainder - full submitMessage pipeline (permanent-vs-transient retry,
  Sent-folder upload, reference flags, gateway stats): large surface in a
  3.3k-line client, heavy transport/Redis mocking.
- P1 #7 - server.js account assignment/reassignment: highest blast radius but
  the orchestration is entangled with module state; needs logic extraction (a
  refactor of a critical orchestrator) or a fake-worker harness.
- P1 #9 - SMTP server + IMAP-proxy auth: those servers are not enabled in the
  shared test config; needs a dedicated server boot with them enabled.
- P1 #10 - bulk message mutate/delete REST: needs a connected mailbox with
  messages; not meaningfully testable against the credential-less test server.
- P1 #12 remainder - OAuth2AppsHandler CRUD encryption / getServiceAccessToken
  caching / getClient: stateful, needs Redis + secret + provider mocking.
- P1 #13 - Gmail history sync + Outlook subscription lifecycle: heavy mocking of
  the 3k-4.5k-line client classes.
- P1 #14 remainder - imap-client reconnect() method + start() error->state
  classification: needs an IMAPClient instance with a mocked ImapFlow + fake
  timers.

Guiding constraint: no unverified or fragile tests were committed. The deferred
items each require infrastructure (extra server, live mailbox, orchestrator
refactor, or large-class mocking) beyond what a test can assert reliably in this
environment.
