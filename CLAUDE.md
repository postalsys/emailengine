# Claude Development Guidelines

## Project Overview

EmailEngine is an email sync platform that provides REST API access to email accounts. It supports IMAP/SMTP, Gmail API, and Microsoft Graph (Outlook) with real-time webhooks for email events.

## Dependency Updates

Always use `npm run update` to bump dependencies - never edit versions in package.json by hand and never run a bare `npx ncu`. The script does a full refresh (`ncu -u` + fresh lockfile + `copy-static-files.sh` + regenerated license listing and gettext catalog); a manual package.json edit skips the artifact regeneration and leaves `static/licenses.html` and the translation catalog stale. Version constraints for packages that must not be upgraded to latest live in `.ncurc.js` with per-package rationale.

## Document Store (deprecated, disabled by default)

The Document Store is disabled by default. It only runs when EmailEngine is started with the `--documentStore.enabled` CLI flag, the `[documentStore] enabled = true` config value, or `EENGINE_DOCUMENT_STORE_ENABLED=true`. The gate is exposed as `documentStoreFeatureEnabled` (sync) and `isDocumentStoreEnabled()` (sync flag AND the `documentStoreEnabled` setting) from `lib/document-store.js`. When the gate is off: the `documents` worker is not spawned, every document-store-only endpoint (`/v1/chat/{account}`, `/v1/unified/search`, `/admin/config/document-store/*`) is unregistered and returns 404, all runtime document-store code takes its existing "disabled" path, and the admin UI shows an error alert if the `documentStoreEnabled` setting is still on. Runtime reads of the `documentStoreEnabled` setting use `isDocumentStoreEnabled()` so the feature-off state reuses the already-tested setting-off paths.

## OpenAPI document

`/swagger.json` is generated in-house by `lib/openapi/` from the route joi schemas - there is no documentation-generator dependency (hapi-swagger was archived upstream and is gone). `joi-schema.js` converts joi `describe()` output into Schema Objects, `build-document.js` walks `server.table()`, `index.js` registers the route. Document-level options (tag list and order, security scheme) live in `lib/swagger-options.js`; per-route documentation metadata lives in each route's `plugins.openapi` block (`responses`, `produces`, `x-ee-behavior`).

The document is a published surface: the README points at it, emailengine.dev mirrors it, and it feeds Postman and code generators. `.label()` on a joi schema is therefore a public type name, and the endpoint is intentionally unauthenticated. Any change that alters the document has to be acknowledged by re-recording `test/fixtures/openapi-golden.json` (see `.claude/rules/testing.md`).

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
- `EENGINE_DOCUMENT_STORE_ENABLED` - Enable the deprecated Document Store feature (default: false; also settable via `--documentStore.enabled` / `[documentStore] enabled`)

**Network trust and egress:**
- `EENGINE_ADMIN_ACCESS_ADDRESSES` - Comma-separated IPs/CIDRs allowed to reach `/admin` (default: unset, no restriction)
- `EENGINE_API_PROXY_ADDRESSES` - Comma-separated IPs/CIDRs of proxies allowed to set `X-Forwarded-For`. Unset means the header is honored from any peer whenever the API proxy setting is on, which is the historical default. Set this whenever you rely on `EENGINE_ADMIN_ACCESS_ADDRESSES` or per-token `restrictions.addresses`, otherwise a client that can reach the port directly picks its own source address. See `lib/utils/network.js` `resolveClientIp()`
- `EENGINE_WEBHOOK_EGRESS_POLICY` - Where webhook deliveries may be sent: `link-local` (default, blocks the cloud instance metadata range), `private` (also blocks RFC1918, loopback, CGNAT, ULA), or `off`. Any policy other than `off` also stops redirects being followed, since a permitted host could otherwise redirect to a blocked one. See `lib/egress-filter.js`

**Queue retention:**
- `EENGINE_QUEUE_REMOVE_AFTER` - Initial value for the `queueKeep` setting: completed entries to retain (default: 0)
- `EENGINE_QUEUE_KEEP_FAILED` - Failed entries retained per queue, regardless of `queueKeep` (default: 500). Failures are the only record that a delivery was given up on, so they are never dropped on arrival; raise or lower this against Redis memory, remembering a `messageNew` payload can carry up to `notifyTextSize` of message text
- `EENGINE_QUEUE_KEEP_FAILED_AGE` - How long failed entries are retained, in seconds (default: 604800, 7 days)

**Message rendering:**
- `EENGINE_DISABLE_THREAD_COLLAPSE` - Set to `true` to stop web-safe HTML from folding quoted thread history into a collapsed `<details class="ee-collapsed-thread">` block (default: folding enabled). The marker carries class names only - its `<summary>` is empty on purpose, so a renderer that does not know about it shows nothing extra. See `lib/web-safe-html.js`

**Prepared configuration** (applied on startup):
- `EENGINE_SETTINGS` - JSON settings object
- `EENGINE_PREPARED_TOKEN` - Base64url msgpack-encoded API token
- `EENGINE_PREPARED_PASSWORD` - Base64url PBKDF2 password hash
- `EENGINE_PREPARED_LICENSE` - License key

## Code Style Rules

- Never use emojis in code or documentation, only printable ASCII characters
- Use a single hyphen-minus (`-`) as a dash in UI copy and user-facing strings. Never use double hyphens (`--`), em dashes, or en dashes.
- When composing git commit messages do not include Claude as co-contributor
- For commits that do not change runtime behavior (docs, comments, CI/workflow tweaks, formatting), append `[skip ci]` to the commit message to avoid triggering the GitHub Actions workflows. Exception: do not add `[skip ci]` to commits using a `fix:` or `feat:` prefix - those must run so the release action is triggered.
- After making code changes:
  1. Run `/simplify` to review changed code for reuse, quality, and efficiency
  2. Run `npm run format` and `npm run lint`
  3. Run `/security-review` to check for security issues before committing
- After pushing, check the GitHub Actions runs for the push (e.g. `gh run list --branch <branch>`) and report their status. If a run fails for a strange or unrelated reason (for example a checkout step reporting "account suspended", HTTP 403, or other auth/infrastructure errors that have nothing to do with the change), check https://www.githubstatus.com/ for an active GitHub incident before assuming the failure is caused by the code.
- Avoid the circuit breaker pattern unless absolutely necessary. EmailEngine processes many independent accounts through shared workers, so a single failing account can trip a circuit breaker and block all other accounts. Prefer per-account error handling (retry with backoff, error state tracking) over global circuit breakers.
- Never suppress or swallow unhandled rejections/exceptions at the global handler level. If an error reaches the global `unhandledRejection` or `uncaughtException` handler, the worker must die -- this is the last line of defense. The correct fix is always to handle the error at the source so it never bubbles up to the global handler. This means adding proper try/catch, .catch(), or error event handlers at the actual call site. If the unhandled rejection originates in a dependency (e.g. ImapFlow), fix it in the dependency itself.

## Dependencies We Maintain

- **ImapFlow** (`../imapflow`): The ImapFlow IMAP client library is maintained by us. The local development copy lives at `../imapflow` relative to this project root. When bugs or unhandled promise rejections originate in ImapFlow, fix them directly in the ImapFlow source rather than working around them in EmailEngine.
