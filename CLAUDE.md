# Claude Development Guidelines

## Project Overview

EmailEngine is an email sync platform that provides REST API access to email accounts. It supports IMAP/SMTP, Gmail API, and Microsoft Graph (Outlook) with real-time webhooks for email events.

## Dependency Updates

Always use `npm run update` to bump dependencies - never edit versions in package.json by hand and never run a bare `npx ncu`. The script does a full refresh (`ncu -u` + fresh lockfile + `copy-static-files.sh` + regenerated license listing and gettext catalog); a manual package.json edit skips the artifact regeneration and leaves `static/licenses.html` and the translation catalog stale. Version constraints for packages that must not be upgraded to latest live in `.ncurc.js` with per-package rationale.

## Document Store (deprecated, disabled by default)

The Document Store is disabled by default. It only runs when EmailEngine is started with the `--documentStore.enabled` CLI flag, the `[documentStore] enabled = true` config value, or `EENGINE_DOCUMENT_STORE_ENABLED=true`. The gate is exposed as `documentStoreFeatureEnabled` (sync) and `isDocumentStoreEnabled()` (sync flag AND the `documentStoreEnabled` setting) from `lib/document-store.js`. When the gate is off: the `documents` worker is not spawned, every document-store-only endpoint (`/v1/chat/{account}`, `/v1/unified/search`, `/admin/config/document-store/*`) is unregistered and returns 404, all runtime document-store code takes its existing "disabled" path, and the admin UI shows an error alert if the `documentStoreEnabled` setting is still on. Runtime reads of the `documentStoreEnabled` setting use `isDocumentStoreEnabled()` so the feature-off state reuses the already-tested setting-off paths.

## MCP endpoint

EmailEngine serves the Model Context Protocol at `POST /mcp` (stateless Streamable HTTP, protocol revisions 2025-06-18/2025-11-25 via `initialize` and 2026-07-28 via per-request `_meta`; GET/DELETE answer 405, sessions are never minted). The protocol code lives in `lib/mcp/` (`protocol.js` is the transport-free state machine, `tools.js` the registry/executor, `resources.js` accounts-as-resources, `listen.js` the `subscriptions/listen` SSE bridge fed from the same change fanout as `/v1/changes`, `oauth.js` the minimal authorization server). Tools are declared per route via a `plugins.mcp` block; everything else (input schema from the joi validators through `lib/mcp/json-schema.js`, annotations from `routeGrant()`) is derived, and every `tools/call` dispatches through `server.inject()` with the caller's own credential, so REST enforcement (scopes, permissions, account binding, restrictions, audit log) applies unchanged. The tool manifest is locked by `test/fixtures/mcp-tools-golden.json` (`UPDATE_MCP_GOLDEN=true npm run test:unit` to re-record). `tools/list` is per-credential advertisement: an account-bound token sees only tools taking an `account` argument, and a permission-narrowed token sees only tools whose grant its record allows (the grant is stored on each registry entry) - enforcement stays on the injected inner request either way.

Gates: `EENGINE_MCP_ENABLED` / `--mcp.enabled` / `[mcp] enabled` (default true) controls route registration; the `mcpEnabled` setting (default false, admin UI Configuration > MCP) turns the endpoint on; `mcpOAuthEnabled` + a configured `serviceUrl` additionally enable OAuth discovery (`/.well-known/oauth-*`), dynamic client registration, the admin consent page `/admin/mcp/authorize`, and the token endpoint.

MCP ships as a quiet beta. The admin UI labels it Beta everywhere it surfaces (side menu entry, config page header and intro alert, the `mcp` scope row on the token form), the endpoint is off by default, and it stays out of `/swagger.json`. Deliberately NOT advertised: no README or docs-site coverage yet, and commits touching MCP use the `fix:` prefix - never `feat:` - so release notes list the work under Bug Fixes instead of headlining a minor release. Keep that stance until the feature graduates; graduation is when the `feat:`-style announcement, public docs and badge removal happen together.

The consent page deliberately lives on the admin surface (`/admin/mcp/authorize`, rendered as a consent dialog in the chrome-free `prompt` admin layout - Tailwind/FlyonUI like the login layout it mirrors - untranslated like the rest of the admin UI), NOT on the framework-free public surface with the hosted auth form: approving mints an instance credential and requires an authenticated admin session, which itself only exists inside the `EENGINE_ADMIN_ACCESS_ADDRESSES` perimeter, so a whitelist-exempt consent page could never approve anything anyway - it would only widen what an unlisted address can probe. Do not move it or restyle it as a public page.

Two behaviors of the consent page are deliberate and easy to "fix" back into problems. **Nothing reachable before the human clicks redirects off the origin**: client registration is open and unauthenticated, so a validated `redirect_uri` is not enough to make an automatic error redirect safe (anyone can register their own address and aim a link at it), and every pre-consent failure therefore renders instead - only approval and Deny redirect. **Deny is checked before the admin-session gate**, because refusing to issue a credential does not require the authority to issue one, and on a passwordless instance the page offers no other button. Both paths offer the same three access levels from `MCP_ACCESS_LEVELS` (`lib/token-permission-view.js`): read-only (`MCP_READ_ONLY_PERMISSIONS`, the default), mail agent (`MCP_MAIL_AGENT_PERMISSIONS`, the non-destructive subset of `SURFACE_GRANTS.mcp` - can send, cannot reach the delete tool), and full (no permissions record, the `mcp` scope itself is the bound). The consent POST defaults an absent `access` field to read-only on purpose - under the old checkbox an omitted field was how full access was requested, so a stale form fails narrow, not wide. `test/mcp-consent-test.js` asserts each level reaches the minted token; MCP-minted tokens are reviewable at `/admin/tokens?scope=mcp` (the tokens listing's scope filter, backed by `tokens.list()` `opts.scope`). The `mcp` token scope is surface-bound: the api-token strategy honors it only on requests carrying `request.app.mcpInternal` (set by `lib/mcp/inject.js`, unreachable from the network) and only for grants listed in `SURFACE_GRANTS.mcp` - `test/mcp-tools-test.js` asserts every exposed tool stays inside that list.

## OpenAPI document

`/swagger.json` is generated in-house by `lib/openapi/` from the route joi schemas - there is no documentation-generator dependency (hapi-swagger was archived upstream and is gone). `joi-schema.js` converts joi `describe()` output into Schema Objects, `build-document.js` walks `server.table()`, `index.js` registers the route. Document-level options (tag list and order, security scheme) live in `lib/swagger-options.js`; per-route documentation metadata lives in each route's `plugins.openapi` block (`responses`, `produces`, `x-ee-behavior`, `x-codeSamples`).

`info.description` (in `workers/api.js`) is rendered both by external consumers and by the admin reference landing page, which shows it instead of prose of its own. Keep it to paragraphs, backtick code spans and absolute links: `lib/api-reference/format.js` escapes first and only adds back a closed tag set, so headings, lists or raw HTML render as visible literal text.

`x-codeSamples` is the standard extension for hand-written per-operation snippets (`[{ lang, source, label? }]`, also read by Redoc and Scalar). The reference page puts them ahead of the generated curl/Node/Python tabs. Reach for one when the synthesized example misrepresents an endpoint - the request body of `POST /v1/account/{account}/message/{message}/submit`, for instance, is entirely optional overrides, which the generated snippet shows as if they were the payload.

The document is a published surface: the README points at it, emailengine.dev mirrors it, and it feeds Postman and code generators. `.label()` on a joi schema is therefore a public type name, and the endpoint is intentionally unauthenticated. Any change that alters the document has to be acknowledged by re-recording `test/fixtures/openapi-golden.json` (see `.claude/rules/testing.md`).

## Security headers

`lib/security-headers.js` stamps every response from an `onPreResponse` extension registered after the error-page one in `workers/api.js`, so error pages, redirects and JSON errors carry the headers too. The request path (plus route tags) picks a profile - `static`, `api`, `admin`, `bullBoard`, `public` - and with it the framing headers, COOP/CORP, `Cache-Control: no-store` and the Content-Security-Policy preset. A view rendered with the public layout takes the public CSP preset even on an admin path (error pages, the branding preview), because that layout carries operator-injected markup; `frame-ancestors` follows the path regardless. The admin policy is nonce-based for scripts and stylesheets: `attachSecurityContext()` mints `request.app.cspNonce` at the top of the `onRequest` extension, the view context exposes it as `cspNonce`, every inline `<script>` in `views/` carries `nonce="{{cspNonce}}"` (`test/views-csp-guardrail-test.js` enforces it, `.claude/rules/admin-ui.md` has the authoring rules), and `style-src-elem` carries the same nonce, so no first-party code appends a `<style>` element: ACE runs with `useStrictCSP` and links its sheets through `views/partials/ace_assets.hbs`, the message browser widget receives `styleNonce`. Style attributes stay allowed (`style-src-attr 'unsafe-inline'`) because sanitised email HTML arrives with every rule inlined into them. A route adjusts single directives through `options.plugins.securityHeaders.directives` (the message browser allows remote images and, until the vendored ee-client carries `styleNonce`, an un-nonced stylesheet; the MCP consent page drops `form-action` because its redirect target is the client's own URI). Machine-facing routes outside `/v1` (`/metrics`, `/swagger.json`, `/mcp`) carry the `external` tag, which is what selects the API profile, JSON errors and the CSRF exemption for them. Public pages stay frameable and get a relaxed policy on purpose. HSTS is sent when `serviceUrl` is https, the same signal that marks the cookies Secure; `Cache-Control` is only filled in where a handler set none. `/static` responses carry no CSP because `static/js/evaluation-worker.js` runs operator code through `new Function` by design.

## Releases

Releases are drafted, not published, by `release-please` (`release-please-config.json`, manifest mode - the `draft` option has no action input, which is why the config file exists). The binaries are built, signed and notarized outside CI by `upload.sh`, which uploads them to the draft and then publishes it. Nobody can reach a version whose binaries do not exist yet.

Three settings in that config are load-bearing, and none of them are cosmetic:

- `include-component-in-tag: false` - it defaults to TRUE, which would tag releases `emailengine-app-v2.77.0` instead of `v2.77.0` and break `upload.sh`, every download URL and the whole tag history.
- `force-tag-creation: true` - GitHub withholds the tag for a draft release, and `upload.sh` builds from the tag (falling back to HEAD behind an interactive prompt without it).
- `draft: true` - what makes the whole flow work.

npm publishes when release-please creates the release, not when the draft is later published - `release_created` reports the release object regardless of its visibility. Deferring it to a `release` event was considered and rejected: draft releases raise no event, and one raised inside Actions by `GITHUB_TOKEN` never triggers a workflow, so such a job would fire only because `upload.sh` publishes with a real user's credentials. Too many conditions, and the failure mode is a silent non-publication. Publishing early is safe because the npm package is the Node source and does not carry the binaries.

The npm job must stay in `.github/workflows/release.yaml`: npm trusted publishing (OIDC, which is why no npm token secret exists) is bound to the repository AND the workflow filename.

## Detailed guidance (loaded on demand)

Path-scoped rules in `.claude/rules/` load automatically when you work with the matching files. Read the relevant one before changing that area:

- `.claude/rules/workers.md` - per-worker behavior and failure contracts (`workers/**`, `lib/email-client/**`, webhook/export/delivery modules)
- `.claude/rules/testing.md` - test tiers, route-table guardrails, test-authoring rules (`test/**`, route modules)
- `.claude/rules/admin-ui.md` - admin UI theme, component partials, build steps, framework-free public pages (`views/**`, `static/**`)

## Authentication Design

- **Passkey (WebAuthn) login is a standalone authentication method.** It intentionally bypasses TOTP. When a user authenticates via passkey, no additional factor is required. This is by design - passkeys are treated as a single sufficient factor.

## Environment Variables

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
- `EENGINE_EXPORT_QC` - Export concurrency per worker (default: 1)
- `EENGINE_EXPORT_TIMEOUT` - Export operation timeout (default: 5 minutes)
- `EENGINE_NOTIFY_QC` - Webhook concurrency per worker (default: 1)
- `EENGINE_SMTP_MAX_CLIENTS` - Maximum concurrent SMTP server connections (default: 100; also `[smtp] maxClients`). Each connection buffers its message in memory up to `EENGINE_MAX_SMTP_MESSAGE_SIZE`, so this bounds the SMTP worker's memory; excess connections are refused with a 421
- `EENGINE_DOCUMENT_STORE_ENABLED` - Enable the deprecated Document Store feature (default: false; also settable via `--documentStore.enabled` / `[documentStore] enabled`)
- `EENGINE_MCP_ENABLED` - Register the MCP endpoint routes (default: true; also settable via `--mcp.enabled` / `[mcp] enabled`). Registration alone serves nothing: the `mcpEnabled` setting (default false) is the runtime switch
- `EENGINE_CSP_MODE` - How the Content-Security-Policy is delivered: `enforce` (default), `report-only` (framing stays enforced, the rest of the policy goes to `Content-Security-Policy-Report-Only` so violations only show in the browser console) or `off` (the framing directive only). Also `[api] cspMode`. The other security headers are not affected by it

**Network trust and egress:**
- `EENGINE_ADMIN_ACCESS_ADDRESSES` - Comma-separated IPs/CIDRs allowed to reach `/admin` (default: unset, no restriction)
- `EENGINE_API_PROXY_ADDRESSES` - Comma-separated IPs/CIDRs of proxies allowed to set `X-Forwarded-For`. Unset means the header is honored from any peer whenever the API proxy setting is on, which is the historical default. Set this whenever you rely on `EENGINE_ADMIN_ACCESS_ADDRESSES` or per-token `restrictions.addresses`, otherwise a client that can reach the port directly picks its own source address. See `lib/utils/network.js` `resolveClientIp()`
- `EENGINE_WEBHOOK_EGRESS_POLICY` - Where webhook deliveries and the IMAP/SMTP autodiscovery lookups (`GET /v1/autoconfig`, the hosted setup form) may be sent: `link-local` (default, blocks the cloud instance metadata range), `private` (also blocks RFC1918, loopback, CGNAT, ULA), or `off`. Any policy other than `off` also stops webhook redirects being followed, since a permitted host could otherwise redirect to a blocked one; autodiscovery follows redirects one vetted hop at a time through `lib/egress-fetch.js`. Enforced twice: `assertAllowedUrl()` refuses a bad destination up front, and `createEgressLookup()` re-applies the policy as the connect-time `lookup` of `httpAgent.webhook`, so the addresses vetted are the addresses connected to. Behind a proxy only the up-front check applies. The policy is owned by `lib/webhook-egress.js`; the classification lives in `lib/egress-filter.js`

**Queue retention:**
- `EENGINE_QUEUE_REMOVE_AFTER` - Initial value for the `queueKeep` setting: completed entries to retain (default: 0)
- `EENGINE_QUEUE_KEEP_FAILED` - Failed entries retained per queue, regardless of `queueKeep` (default: 500). Failures are the only record that a delivery was given up on, so they are never dropped on arrival; raise or lower this against Redis memory, remembering a `messageNew` payload can carry up to `notifyTextSize` of message text
- `EENGINE_QUEUE_KEEP_FAILED_AGE` - How long failed entries are retained, in seconds (default: 604800, 7 days)

**Token audit log** (only written when the `tokenAuditLog` setting is on, off by default):
- `EENGINE_TOKEN_LOG_ENTRIES` - Requests retained per access token (default: 1000). Every write trims, so this bounds the feature's whole storage cost: a full log of typical entries is roughly 170KB of Redis per token, and it is the token count that scales it, not request volume. Values below 1 fall back to the default rather than being clamped
- `EENGINE_TOKEN_LOG_AGE` - How long a token's log survives its last use, in seconds (default: 604800, 7 days). Refreshed on every write, so a token nobody uses takes its log with it

**Message rendering:**
- `EENGINE_DISABLE_THREAD_COLLAPSE` - Set to `true` to stop web-safe HTML from folding quoted thread history into a collapsed `<details class="ee-collapsed-thread">` block (default: folding enabled). The marker carries class names only - its `<summary>` is empty on purpose, so a renderer that does not know about it shows nothing extra. See `lib/web-safe-html.js`

**Prepared configuration** (applied on startup):
- `EENGINE_SETTINGS` - JSON settings object, re-applied through `settings.set()` on every boot, so a value saved for one of its keys in the admin UI reverts at the next restart. The key list is recorded as the `preparedSettingsKeys` setting, which `lib/ui-routes/settings-page.js` turns into `envManagedKeys` in every settings-form view context so the page can flag those fields
- `EENGINE_PREPARED_TOKEN` - Base64url msgpack-encoded API token
- `EENGINE_PREPARED_PASSWORD` - Base64url PBKDF2 password hash. Written only when it differs from the stored hash: the write bumps `passwordVersion`, which ends every admin session and message-browser token
- `EENGINE_PREPARED_LICENSE` - License key

## Code Style Rules

- Never use emojis in code or documentation, only printable ASCII characters
- Use a single hyphen-minus (`-`) as a dash in UI copy and user-facing strings. Never use double hyphens (`--`), em dashes, or en dashes.
- When composing git commit messages do not include Claude as co-contributor
- Prefer the `fix:` conventional-commit prefix for changes that alter runtime behavior. `feat:` is reserved for a genuinely new, noticeable capability a user would look for in the changelog - a new endpoint, a new setting, a new provider. Raising a limit, tightening a bound, reworking internals or improving existing behavior is a `fix:` even when the diff is large, because the prefix drives the release notes and a minor bump promises users something new to try.
- For commits that do not change runtime behavior (docs, comments, CI/workflow tweaks, formatting), append `[skip ci]` to the commit message to avoid triggering the GitHub Actions workflows. Exception: do not add `[skip ci]` to commits using a `fix:` or `feat:` prefix - those must run so the release action is triggered. GitHub reads the marker off the HEAD commit of a push, not off each commit in it, so a `[skip ci]` docs commit pushed on top of a `fix:` commit silences the workflows for both and the release PR is never opened. When a push mixes the two, the release-triggering commit has to be last. Never quote the marker literally in a commit message body either, not even when writing about it - GitHub matches it anywhere in the message, so a commit explaining the rule skips itself. There is no repairing any of it afterwards: `master` is protected against force-pushes, so the only way back is another commit.
- After making code changes:
  1. Run `/simplify` to review changed code for reuse, quality, and efficiency
  2. Run `npm run format` and `npm run lint`
  3. Run `/security-review` to check for security issues before committing
- After pushing, check the GitHub Actions runs for the push (e.g. `gh run list --branch <branch>`) and report their status. If a run fails for a strange or unrelated reason (for example a checkout step reporting "account suspended", HTTP 403, or other auth/infrastructure errors that have nothing to do with the change), check https://www.githubstatus.com/ for an active GitHub incident before assuming the failure is caused by the code.
- Avoid the circuit breaker pattern unless absolutely necessary. EmailEngine processes many independent accounts through shared workers, so a single failing account can trip a circuit breaker and block all other accounts. Prefer per-account error handling (retry with backoff, error state tracking) over global circuit breakers.
- Never suppress or swallow unhandled rejections/exceptions at the global handler level. If an error reaches the global `unhandledRejection` or `uncaughtException` handler, the worker must die -- this is the last line of defense. The correct fix is always to handle the error at the source so it never bubbles up to the global handler. This means adding proper try/catch, .catch(), or error event handlers at the actual call site. If the unhandled rejection originates in a dependency (e.g. ImapFlow), fix it in the dependency itself.

## Dependencies We Maintain

- **ImapFlow** (`../imapflow`): The ImapFlow IMAP client library is maintained by us. The local development copy lives at `../imapflow` relative to this project root. When bugs or unhandled promise rejections originate in ImapFlow, fix them directly in the ImapFlow source rather than working around them in EmailEngine.
