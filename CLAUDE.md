# Claude Development Guidelines

## Project Overview

EmailEngine is an email sync platform that provides REST API access to email accounts. It supports IMAP/SMTP, Gmail API, and Microsoft Graph (Outlook) with real-time webhooks for email events.

## Dependency Updates

Always use `npm run update` to bump dependencies - never edit versions in package.json by hand and never run a bare `npx ncu`. The script does a full refresh (`ncu -u` + fresh lockfile + `copy-static-files.sh` + regenerated license listing and gettext catalog); a manual package.json edit skips the artifact regeneration and leaves `static/licenses.html` and the translation catalog stale. Version constraints for packages that must not be upgraded to latest live in `.ncurc.js` with per-package rationale.

## MCP endpoint

EmailEngine serves the Model Context Protocol at `POST /mcp` (code in `lib/mcp/`; tools are declared per route in a `plugins.mcp` block and dispatched through `server.inject()` with the caller's own credential). It ships as a quiet beta: labelled Beta in the admin UI, off by default (`mcpEnabled` setting), absent from `/swagger.json` and the README, and commits touching MCP use the `fix:` prefix, never `feat:`, so release notes do not headline it. Keep that stance until the feature graduates, when the `feat:`-style announcement, public docs and badge removal happen together. The protocol, the two MCP scopes and their surfaces, the consent page and the grantable groups are in `.claude/rules/mcp.md`, which loads when you touch those files.

## Queue browser

`/admin/queues` is the in-house browser for the BullMQ queues (it replaced bull-board on 2026-10-14). A queued message's content lives outside its job, so every submit-queue action goes through `lib/outbox.js`, never a bare BullMQ job call. Details in `.claude/rules/queue-browser.md`.

## OpenAPI document

`/swagger.json` is generated in-house by `lib/openapi/` from the route joi schemas - there is no documentation-generator dependency (hapi-swagger was archived upstream and is gone). `joi-schema.js` converts joi `describe()` output into Schema Objects, `build-document.js` walks `server.table()`, `index.js` registers the route. Document-level options (tag list and order, security scheme) live in `lib/swagger-options.js`; per-route documentation metadata lives in each route's `plugins.openapi` block (`responses`, `produces`, `x-ee-behavior`, `x-codeSamples`).

`info.description` (in `workers/api.js`) is rendered both by external consumers and by the admin reference landing page, which shows it instead of prose of its own. Keep it to paragraphs, backtick code spans and absolute links: `lib/api-reference/format.js` escapes first and only adds back a closed tag set, so headings, lists or raw HTML render as visible literal text.

`x-codeSamples` is the standard extension for hand-written per-operation snippets (`[{ lang, source, label? }]`, also read by Redoc and Scalar). The reference page puts them ahead of the generated curl/Node/Python tabs. Reach for one when the synthesized example misrepresents an endpoint - the request body of `POST /v1/account/{account}/message/{message}/submit`, for instance, is entirely optional overrides, which the generated snippet shows as if they were the payload.

The document is a published surface: the README points at it, emailengine.dev mirrors it, and it feeds Postman and code generators. `.label()` on a joi schema is therefore a public type name, and the endpoint is intentionally unauthenticated. Any change that alters the document has to be acknowledged by re-recording `test/fixtures/openapi-golden.json` (see `.claude/rules/testing.md`).

## Email autodiscovery

`lib/autodetect-imap-settings.js` resolves IMAP/SMTP settings for an address (MX first, then SRV, `.well-known`, autoconfig, ISPDB and Exchange autodiscovery racing). The Exchange requirements, the rules for when a password may be offered, and the hosted form's skip of the server settings step are in `.claude/rules/autodiscovery.md`.

## One-time passcodes (OTP-Token)

`otp: { code, origin }` on `POST /v1/account/{account}/submit` (and per mail merge entry) becomes the `OTP-Token` header of draft-goto-otp-token, written by nodemailer's `MailComposer` (from 10.3.1; before that only its mailer applied the option, so EmailEngine's direct `MailComposer` use dropped it). An invalid value is an `EOTP` error that `getRawEmail()` turns into a 400, and `useStructuredFormat` refuses an otp outright because a structured Graph send carries no header but `X-*` ones. Reading goes the other way through `lib/otp.js`: mailparser's `parseOtpToken()` applies the draft's rules (exactly one header, an https origin) and the message details of all three backends carry `otp: { code, origin, authenticated }`. The header itself is unauthenticated, so `authenticated` is true only when the topmost `Authentication-Results` written by a server `authenticationTrust()` trusts (Google, Microsoft; the same rule as the AI summary) records a passing DKIM signature from the origin's organizational domain - every other mailbox reports false, never a guess. The messageNew payload carries `otp` only while the `notifyHeaders` setting lists `OTP-Token` (or `*`), because the draft keeps the passcode out of sight of people and a webhook copies it to every receiver; the fetch path asks for the authentication headers only then. The draft expires on 25 March 2027: check for a newer revision before then.

## Security headers

`lib/security-headers.js` stamps every response, and the admin CSP is nonce-based: every inline `<script>` in `views/` carries `nonce="{{cspNonce}}"` and `data-cfasync="false"` (enforced by `test/views-csp-guardrail-test.js`). Profiles, per-route directive overrides and the `form-action` redirect rule are in `.claude/rules/security-headers.md`.

## Device-bound admin sessions (DBSC)

`lib/dbsc/` binds an admin session to a device-held key behind the `dbscEnabled` setting (default off, Beta, quiet like MCP: `fix:` commits, no README). Several of its behaviors look like bugs and are deliberate (nothing deletes a binding, a session binds once); read `.claude/rules/dbsc.md` before changing it.

## Releases

Releases are drafted, not published, by `release-please` (`release-please-config.json`, manifest mode - the `draft` option has no action input, which is why the config file exists). The binaries are built, signed and notarized outside CI by `upload.sh`, which uploads them to the draft and then publishes it. Nobody can reach a version whose binaries do not exist yet.

Three settings in that config are load-bearing, and none of them are cosmetic:

- `include-component-in-tag: false` - it defaults to TRUE, which would tag releases `emailengine-app-v2.77.0` instead of `v2.77.0` and break `upload.sh`, every download URL and the whole tag history.
- `force-tag-creation: true` - GitHub withholds the tag for a draft release, and `upload.sh` builds from the tag (falling back to HEAD behind an interactive prompt without it).
- `draft: true` - what makes the whole flow work.

npm publishes when release-please creates the release, not when the draft is later published - `release_created` reports the release object regardless of its visibility. Deferring it to a `release` event was considered and rejected: draft releases raise no event, and one raised inside Actions by `GITHUB_TOKEN` never triggers a workflow, so such a job would fire only because `upload.sh` publishes with a real user's credentials. Too many conditions, and the failure mode is a silent non-publication. Publishing early is safe because the npm package is the Node source and does not carry the binaries.

The npm job must stay in `.github/workflows/release.yaml`: npm trusted publishing (OIDC, which is why no npm token secret exists) is bound to the repository AND the workflow filename.

## TLS certificates

Every TLS listener (SMTP server, IMAP proxy, API) asks `lib/tls/context.js` what to serve: environment material, then an uploaded certificate, then Let's Encrypt, then a self-signed fallback. Nothing orders a certificate in the foreground (`lib/tls/provision.js` is the only caller of `acquireCert`). Precedence, catalog ids, provisioning gates and the status page rules are in `.claude/rules/tls.md`.

## Detailed guidance (loaded on demand)

Path-scoped rules in `.claude/rules/` load automatically when you work with the matching files. Read the relevant one before changing that area:

- `.claude/rules/workers.md` - per-worker behavior and failure contracts (`workers/**`, `lib/email-client/**`, webhook/export/delivery modules)
- `.claude/rules/testing.md` - test tiers, route-table guardrails, test-authoring rules (`test/**`, route modules)
- `.claude/rules/admin-ui.md` - admin UI theme, component partials, build steps, framework-free public pages (`views/**`, `static/**`)
- `.claude/rules/mcp.md` - MCP protocol, scopes, consent page, grantable groups, privileged settings
- `.claude/rules/tls.md` - certificate precedence, catalog, provisioning, the TLS page
- `.claude/rules/autodiscovery.md` - IMAP/SMTP autodiscovery and the Exchange requirements
- `.claude/rules/queue-browser.md` - the queue browser and outbox actions
- `.claude/rules/security-headers.md` - security headers and the nonce CSP
- `.claude/rules/dbsc.md` - device-bound admin sessions

## Authentication Design

- **Passkey (WebAuthn) login is a standalone authentication method.** It intentionally bypasses TOTP. When a user authenticates via passkey, no additional factor is required. This is by design - passkeys are treated as a single sufficient factor.

## Environment Variables

`ENVIRONMENT.md` is the complete operator-facing list, and `test/env-docs-guardrail-test.js` fails when the code reads an `EENGINE_*` variable it does not list (or it lists one nothing reads). The entries below are the ones whose behavior needs more than a table row. Seven limits that used to be environment-only are settings too (`disableThreadCollapse`, `queueKeepFailed`, `queueKeepFailedAge`, `queueKeepFailedContent`, `queueKeepFailedContentSize`, `tokenLogEntries`, `tokenLogAge`): `lib/env-setting-overrides.js` resolves each one with the environment variable winning over the setting and the setting over the default, reads them through a ten-second per-process cache, and the settings pages flag a field whose variable is set (`envOverriddenSettings`) and do not save a value for it, so the pinned environment value is never copied into a setting that would outlive the variable. The token log limits are privileged settings like `tokenAuditLog`: a narrowed credential must not be able to shrink the audit trail its own requests land in.

**Core:**

- `EENGINE_REDIS` / `REDIS_URL` - Redis connection URI (default: `redis://127.0.0.1:6379/8`)
- `EENGINE_PORT` / `PORT` - API server port (default: 3000)
- `EENGINE_HOST` - API server bind address (default: 127.0.0.1)
- `EENGINE_TIMEOUT` - Command timeout in ms (default: 10000)
- `EENGINE_LOG_LEVEL` - Logging level (default: trace)
- `EENGINE_BEACON_DISABLED` - Set to `true` to opt out of the feature beacon (anonymized feature-usage diagnostics piggybacked on the existing license-validation call). License validation itself is unaffected. See `lib/license-beacon.js`.

**Workers:**

- `EENGINE_WORKERS` - IMAP worker count (default: 4)
- `EENGINE_WORKERS_API` - API/HTTP worker count (default: 1; values >1 need `SO_REUSEPORT`/Linux, otherwise falls back to 1)
- `EENGINE_WORKERS_WEBHOOKS` - Webhook worker count (default: 1)
- `EENGINE_WORKERS_SUBMIT` - Submit worker count (default: 1)
- `EENGINE_WORKERS_EXPORT` - Export worker count (default: 1; also `--workers.export` / `[workers] export`)
- `EENGINE_EXPORT_QC` - Export concurrency per worker (default: 1)
- `EENGINE_EXPORT_TIMEOUT` - Export operation timeout (default: 5 minutes)
- `EENGINE_NOTIFY_QC` - Webhook concurrency per worker (default: 1)
- `EENGINE_IMAP_STALE_CHECK_INTERVAL` - Quiet period (e.g. `1h`) after which a resync pass checks the main mailbox over the command connection and reconnects an IMAP account whose primary connection has stopped seeing new messages (default: unset, disabled). See `checkStaleMainView()` in `lib/email-client/imap-client.js`
- `EENGINE_OUTLOOK_FALLBACK_POLL_INTERVAL` - How often each connected MS Graph account runs a missed-notification recovery pass, catching new messages whose change notification Graph dropped without sending a `missed` lifecycle event (duration, default `10m`, `0` disables, never below 10 s). A pass that missed nothing is one Graph listing request. See `setupFallbackPollTimer()` in `lib/email-client/outlook-client.js`
- `EENGINE_SMTP_MAX_CLIENTS` - Maximum concurrent SMTP server connections (default: 100; also `[smtp] maxClients`). Each connection buffers its message in memory up to `EENGINE_MAX_SMTP_MESSAGE_SIZE`, so this bounds the SMTP worker's memory; excess connections are refused with a 421
- `EENGINE_IMAPPROXY_MAX_CLIENTS` - Maximum concurrent IMAP proxy connections, counted from accept (default: 1000; also `[imap] maxClients`). Excess connections get `* BYE Too many connections` and are closed. Before login a command may carry at most 32 literals and the state rule runs before any literal is accepted, so an unauthenticated client cannot buffer APPEND data; with the PROXY protocol on, the header must arrive within `proxyHeaderTimeout` (10 s)
- `EENGINE_MCP_ENABLED` - Register the MCP endpoint routes (default: true; also settable via `--mcp.enabled` / `[mcp] enabled`). Registration alone serves nothing: the `mcpEnabled` setting (default false) is the runtime switch
- `EENGINE_CSP_MODE` - How the Content-Security-Policy is delivered: `enforce` (default), `report-only` (framing stays enforced, the rest of the policy goes to `Content-Security-Policy-Report-Only` so violations only show in the browser console) or `off` (the framing directive only). Also `[api] cspMode`. The other security headers are not affected by it

**Network trust and egress:**

- `EENGINE_HTTP_PROXY_ENABLED` / `EENGINE_HTTP_PROXY_URL` - Override the `httpProxyEnabled` / `httpProxyUrl` settings (the dedicated proxy for outbound HTTP/HTTPS). Every outbound HTTP/HTTPS request goes through the shared dispatchers in `lib/tools.js` (`httpAgent.fetch`, `.retry`, `.webhook`, and `.live` for long-lived clients such as ACME), whose proxy is picked by `resolveHttpProxy()`: the dedicated HTTP proxy when it is enabled and has a URL, otherwise the global `proxyEnabled` / `proxyUrl` proxy that IMAP and SMTP connections use, so one setting covers Gmail API, Microsoft Graph, OAuth2, webhooks, license validation, update checks, ACME, OpenAI and Sentry. `EENGINE_HTTP_PROXY_ENABLED=false` is the one way to keep IMAP/SMTP on a proxy while HTTP goes direct. The main thread resolves the proxy before spawning and passes it to every worker as `workerData.httpProxyUrl`, so `lib/tools.js` builds the dispatchers at module load and refreshes them itself from the `settings` broadcast (`maybeReloadHttpProxyAgent()`, a no-op when the resolved proxy is unchanged); a new worker type or outbound call needs no proxy wiring, only one of the shared dispatchers rather than a bare `fetch()`. The exception is traffic made for one account: an OAuth2 client built with `oauth2Apps.getClient(id, { route })` sends every token and API request through `httpAgent.forRoute(route)`. The route comes from `getAccountHttpRoute()` in `lib/utils/network.js` and mirrors the account's IMAP connection: its own `proxy`, otherwise the `localAddresses` / `imapStrategy` pick, which applies only while no instance-wide HTTP proxy is in use. That is why the admin UI labels `imapStrategy` "Mailbox access" and `smtpStrategy` "Sending over SMTP"; the keys keep their historical names. A client built without one (Pub/Sub setup, app verification) stays on the shared dispatchers.
- `EENGINE_ADMIN_ACCESS_ADDRESSES` - Comma-separated IPs/CIDRs allowed to reach `/admin` (default: unset, no restriction)
- `EENGINE_API_PROXY_ADDRESSES` - Comma-separated IPs/CIDRs of proxies allowed to set `X-Forwarded-For`. Unset means the header is honored from any peer whenever the API proxy setting is on, which is the historical default. Set this whenever you rely on `EENGINE_ADMIN_ACCESS_ADDRESSES` or per-token `restrictions.addresses`, otherwise a client that can reach the port directly picks its own source address. See `lib/utils/network.js` `resolveClientIp()`
- `EENGINE_WEBHOOK_EGRESS_POLICY` - Where webhook deliveries and the IMAP/SMTP autodiscovery lookups (`GET` and `POST /v1/autoconfig`, the hosted setup form) may be sent: `link-local` (default, blocks the cloud instance metadata range), `private` (also blocks RFC1918, loopback, CGNAT, ULA), or `off`. Any policy other than `off` also stops webhook redirects being followed, since a permitted host could otherwise redirect to a blocked one; autodiscovery follows redirects one vetted hop at a time through `lib/egress-fetch.js`. Enforced twice: `assertAllowedUrl()` refuses a bad destination up front, and `createEgressLookup()` re-applies the policy as the connect-time `lookup` of `httpAgent.webhook`, so the addresses vetted are the addresses connected to. Behind a proxy only the up-front check applies. The policy covers the discovery requests themselves, not the IMAP and SMTP servers they discover: the mail servers EmailEngine then connects to are chosen by the address domain's own DNS records and are not filtered (see the note in `lib/tools.js`). The policy is owned by `lib/webhook-egress.js`; the classification lives in `lib/egress-filter.js`
- `EENGINE_GCP_METADATA_HOST` - Where a Cloud Pub/Sub app using the attached service account (`authMethod: 'metadataServer'`) reaches the Google Cloud metadata server: `host`, `host:port` or `http://host[:port]` (default `metadata.google.internal`; Google's own `GCE_METADATA_HOST` is read when this is unset). Only the host moves - the paths, the `Metadata-Flavor: Google` header and the http scheme are fixed - and it is deliberately an environment value, never an app field or setting: the request bypasses the HTTP proxy and the egress policy, and the verify report echoes what came back, so a host a narrowed API token could choose would be a probe of the instance's own network. A malformed value is an error, not a fallback to the default. The method is Pub/Sub-only because the metadata server's token is the service account's own and cannot do domain-wide delegation, and `assertNoAttachedIdentity()` refuses it on `POST /v1/oauth2` for a narrowed credential (the app would act as the deployment's own cloud identity in whatever project the payload names, with nothing of the caller's). See `lib/oauth/gcp-metadata.js`

**TLS certificates:**

- `EENGINE_API_TLS` - serve the API and admin UI over HTTPS (also `[api] tls`). `EENGINE_API_TLS_CERT` / `_KEY` / `_CA` / `_PASSPHRASE` / `_CIPHERS` / `_MIN_VERSION` / `_MAX_VERSION` supply the material, and `[api.tls] certPath` / `keyPath` read it from files. Anything left unset falls back to what EmailEngine manages itself (uploaded, Let's Encrypt, self-signed), so an instance that already holds a certificate for its own service domain does not need a second pipeline to serve it here
- `EENGINE_SMTP_TLS_*` and `EENGINE_IMAPPROXY_TLS_*` - the same variable names for the SMTP server and the IMAP proxy. Neither reads a `*_PATH` variable: point `EENGINE_SMTP_TLS_CERT_FILE` at the file instead (the `_FILE` convention `readEnvValue()` applies to every environment value), or paste the PEM into the variable itself. Material supplied this way outranks every certificate EmailEngine manages

**TLS certificate provisioning (ACME):**

- `EENGINE_ACME_DIRECTORY_URL` / `EENGINE_ACME_ENVIRONMENT` - The CA directory Let's Encrypt certificates are ordered from (default: `https://acme-v02.api.letsencrypt.org/directory`) and the name of the stored ACME account record (default: `emailengine`). Override both or neither: the environment names the account record and the directory names the CA that issued it, so moving one alone presents an account key the other CA has never seen and every request is rejected. `lib/cert-handler.js` logs a warning when only one of them is set, since nothing in the CA's rejection says why. Point them at `https://acme-staging-v02.api.letsencrypt.org/directory` plus a distinct environment name to rehearse issuance - staging has the same asynchronous order finalization as production and no rate limits worth worrying about, but its certificates are signed by an untrusted root, so it must never be what a build ships. `lib/cert-handler.js` is the single place that constructs `@postalsys/certs`; all three workers that touch certificates (API, SMTP server, IMAP proxy) get their handler from it, and `test/acme-config-guardrail-test.js` keeps it that way

**Queue retention** (the four failed-entry bounds are also settings, see above):

- `EENGINE_QUEUE_REMOVE_AFTER` - Initial value for the `queueKeep` setting: completed entries to retain (default: 0)
- `EENGINE_QUEUE_KEEP_FAILED` - Failed entries retained per queue, at least (default: 500); a `queueKeep` setting above it raises the count, so the queue page names whichever of the two applies. Failures are the only record that a delivery was given up on, so they are never dropped on arrival; raise or lower this against Redis memory, remembering a `messageNew` payload can carry up to `notifyTextSize` of message text
- `EENGINE_QUEUE_KEEP_FAILED_AGE` - How long failed entries are retained, in seconds (default: 604800, 7 days)
- `EENGINE_QUEUE_KEEP_FAILED_CONTENT` / `EENGINE_QUEUE_KEEP_FAILED_CONTENT_SIZE` - How many of the most recent failed messages keep their raw content so they can be retried (default: 100), and how much content that may add up to in total (default: 100MB, a byte size). Content is dropped oldest first past either bound, past the failed-job age, and whenever the failed job itself is gone; `0` keeps none, which is how it was before failed messages could be retried. See `lib/outbox.js`

**Token audit log** (both limits are also settings, see above; only written when the `tokenAuditLog` setting is on, off by default):

- `EENGINE_TOKEN_LOG_ENTRIES` - Requests retained per access token (default: 1000). Every write trims, so this bounds the feature's whole storage cost: a full log of typical entries is roughly 170KB of Redis per token, and it is the token count that scales it, not request volume. Values below 1 fall back to the default rather than being clamped
- `EENGINE_TOKEN_LOG_AGE` - How long a token's log survives its last use, in seconds (default: 604800, 7 days). Refreshed on every write, so a token nobody uses takes its log with it

**Message rendering:**

- `EENGINE_DISABLE_THREAD_COLLAPSE` - Overrides the `disableThreadCollapse` setting. Set to `true` to stop web-safe HTML from folding quoted thread history into a collapsed `<details class="ee-collapsed-thread">` block (default: folding enabled). The marker carries class names only - its `<summary>` is empty on purpose, so a renderer that does not know about it shows nothing extra. See `lib/web-safe-html.js`

**Prepared configuration** (applied on startup):

- `EENGINE_SETTINGS` - JSON settings object, re-applied through `settings.set()` on every boot, so a value saved for one of its keys in the admin UI reverts at the next restart. The key list is recorded as the `preparedSettingsKeys` setting, which `lib/ui-routes/settings-page.js` turns into `envManagedKeys` in every settings-form view context so the page can flag those fields
- `EENGINE_PREPARED_TOKEN` - Base64url msgpack-encoded API token
- `EENGINE_PREPARED_PASSWORD` - Base64url PBKDF2 password hash. Written only when it differs from the stored hash: the write bumps `passwordVersion`, which ends every admin session and message-browser token
- `EENGINE_PREPARED_LICENSE` - License key

## Pure JavaScript only

EmailEngine ships as a single-file binary for Linux x64, macOS (x64 and arm64) and Windows x64 - the `pkg.targets` list in `package.json`, which the release assets match - and it also runs from npm on whatever Node the operator already has. Two rules follow from that, and neither has an exception:

- **No compiled dependencies.** Never add a package with a native addon, a `node-gyp` build step, prebuilt binaries or a WASM blob, and never write one. Everything must be pure JavaScript that `pkg` can bundle and that runs unchanged on every target. When a task seems to need one (cryptography, image handling, parsing), it is done with Node's own built-in modules instead: `crypto` generates keys and signs, and `lib/tls/self-signed.js` builds an X.509 certificate out of `crypto` plus a small DER writer for exactly this reason. The one form of WASM that is fine is WASM inlined into a package's JavaScript that runs on every target unchanged, as undici does with its llhttp parser (the same parser Node.js core embeds): nothing is compiled at install time and no separate `.wasm` or `.node` file has to ship. A separately shipped `.wasm`/`.node` artifact or a platform-specific optional package is still out.
- **No shelling out.** Never invoke a CLI tool at runtime (`openssl`, `dig`, `curl`, `sh`, ...). None of them is guaranteed to exist on a customer's machine, several do not exist on Windows at all, and a `pkg` binary carries no shell of its own. Do the work in JavaScript. This applies to tests as well: a test that shells out to `openssl` fails on the platforms that matter most.

- **Node.js 22.19 is the minimum.** `lib/node-version.js` holds two thresholds: `server.js` refuses to start below `MIN_NODE` (22.19.0, what undici 8 needs; it throws when loaded on anything older) and prints the commands to upgrade, and `engines.node` declares `^22.22.2 || ^24.15.0 || >=26.0.0`, the range the jsdom bundled in `@postalsys/email-text-tools` declares. A release between the two starts, logs a warning, and the dashboard and `/admin/upgrade` say it is outside the supported range. Runtime code, tests and tooling have to work on Node 22, 24 and later. CI's unit job runs Node 24 and exactly 22.19.0, and the `node_floor` job checks that Node 20 stops with the message. Until 2026-11 the floor was Node 20, held there by the DigitalOcean one-click droplets that upgrade EmailEngine but not the Node.js under it; that was given up to fix a heap leak only jsdom 31 and juice 12 fix, so a droplet on Node 20 stops at its next upgrade with the upgrade commands in its log.
- **The runtime dependency graph is CommonJS only.** `pkg` snapshots a CommonJS module graph and cannot load ES modules, so `require()` of every runtime dependency has to work with `--no-experimental-require-module`. Node 22+ enables require(esm) by default, which hides an ESM-only dependency in development and tests until a binary is built. Never add or upgrade to an ESM-only package, and a CommonJS wrapper that only does a dynamic `import()` of ESM code does not count. When a dependency goes ESM-only, pin its last CommonJS release in `.ncurc.js` (`reject` or `target`) with the reason, so `npm run update` cannot move it. The worked examples are `marked` and `he`, held on their last CommonJS releases in `.ncurc.js`. When a transitive dependency goes ESM-only, a `package.json` `overrides` entry pins it, and an override in one of our libraries does not propagate to EmailEngine, so this repo has to carry its own. Where one of our libraries depends on an ESM-only package it cannot replace, the library can instead bundle it into real CommonJS at build time: `@postalsys/email-text-tools` does that for jsdom (from 2.6.3) and juice (from 3.0.0), which is what took jsdom, juice and their ESM-only dependencies out of this tree; `list-generate.js` reads the bundled packages from each such package's `dist/vendor/*.packages.json` so they still reach the license listing and its license gate. Check with `npm run test:cjs`, which runs the unit tier with `NODE_OPTIONS=--no-experimental-require-module`; CI runs it on the Node 24 unit leg.

Build-time-only devDependencies (tailwindcss, playwright, pkg itself) are not covered by this: they never reach a running instance.

## Code Style Rules

- Never use emojis in code or documentation, only printable ASCII characters
- Use a single hyphen-minus (`-`) as a dash in UI copy and user-facing strings. Never use double hyphens (`--`), em dashes, or en dashes.
- When composing git commit messages do not include Claude as co-contributor
- Prefer the `fix:` conventional-commit prefix for changes that alter runtime behavior. `feat:` is reserved for a genuinely new, noticeable capability a user would look for in the changelog - a new endpoint, a new setting, a new provider. Raising a limit, tightening a bound, reworking internals or improving existing behavior is a `fix:` even when the diff is large, because the prefix drives the release notes and a minor bump promises users something new to try.
- For commits that do not change runtime behavior (docs, comments, CI/workflow tweaks, formatting), append `[skip ci]` to the commit message to avoid triggering the GitHub Actions workflows. Exception: do not add `[skip ci]` to commits using a `fix:` or `feat:` prefix - those must run so the release action is triggered. GitHub reads the marker off the HEAD commit of a push, not off each commit in it, so a `[skip ci]` docs commit pushed on top of a `fix:` commit silences the workflows for both and the release PR is never opened. When a push mixes the two, the release-triggering commit has to be last. Never quote the marker literally in a commit message body either, not even when writing about it - GitHub matches it anywhere in the message, so a commit explaining the rule skips itself. There is no repairing any of it afterwards: `master` is protected against force-pushes, so the only way back is another commit.
- After making code changes:
    1. Run `/simplify` to review changed code for reuse, quality, and efficiency
    2. If the change touches the front end (`views/`, `static/`, admin UI or public pages), review it as a principal UX expert and SaaS product expert. Run the app and take screenshots of every affected page and state (Playwright is already a devDependency), including light and dark themes and a narrow viewport where relevant, then look at them and judge layout, hierarchy, spacing, copy, consistency with the rest of the admin UI, empty and error states, and whether the flow makes sense to an operator. If anything needs improving UX- or design-wise, fix it and re-screenshot until it holds up; do not stop at "the code looks right"
    3. Run `npm run format` and `npm run lint`
    4. Run `/security-review` to check for security issues before committing
- After pushing, check the GitHub Actions runs for the push (e.g. `gh run list --branch <branch>`) and report their status. If a run fails for a strange or unrelated reason (for example a checkout step reporting "account suspended", HTTP 403, or other auth/infrastructure errors that have nothing to do with the change), check https://www.githubstatus.com/ for an active GitHub incident before assuming the failure is caused by the code.
- Avoid the circuit breaker pattern unless absolutely necessary. EmailEngine processes many independent accounts through shared workers, so a single failing account can trip a circuit breaker and block all other accounts. Prefer per-account error handling (retry with backoff, error state tracking) over global circuit breakers.
- Never suppress or swallow unhandled rejections/exceptions at the global handler level. If an error reaches the global `unhandledRejection` or `uncaughtException` handler, the worker must die -- this is the last line of defense. The correct fix is always to handle the error at the source so it never bubbles up to the global handler. This means adding proper try/catch, .catch(), or error event handlers at the actual call site. If the unhandled rejection originates in a dependency (e.g. ImapFlow), fix it in the dependency itself.

## Dependencies We Maintain

- **ImapFlow** (`../imapflow`): The ImapFlow IMAP client library is maintained by us. The local development copy lives at `../imapflow` relative to this project root. When bugs or unhandled promise rejections originate in ImapFlow, fix them directly in the ImapFlow source rather than working around them in EmailEngine.
