# Claude Development Guidelines

## Project Overview

EmailEngine is an email sync platform that provides REST API access to email accounts. It supports IMAP/SMTP, Gmail API, and Microsoft Graph (Outlook) with real-time webhooks for email events.

## Project Structure

- `server.js` - Main process orchestrator (see Main Process section)
- `/bin` - CLI executable entry point
- `/lib` - Core library modules (account, OAuth, email clients, API routes)
- `/lib/email-client` - Email client implementations (IMAP, Gmail API, Outlook Graph)
- `/lib/api-routes` - REST API route handlers
- `/lib/ui-routes` - Web UI route handlers
- `/lib/lua` - Redis Lua scripts for atomic operations
- `/lib/oauth` - OAuth provider implementations
- `/lib/imapproxy` - IMAP proxy server implementation
- `/workers` - Worker thread modules (8 worker types, see Workers section)
- `/test` - Unit and integration tests
- `/config` - TOML configuration files
- `/views` - Handlebars templates for web UI
- `/static` - Frontend assets (CSS, JS)
- `/translations` - i18n translation files (7 languages)

### Key Files

- `lib/account.js` - Account class, manages IMAP/SMTP interactions
- `lib/account/account-state.js` - Account state machine
- `lib/email-client/base-client.js` - Base email client class
- `lib/email-client/gmail-client.js` - Gmail API integration
- `lib/email-client/outlook-client.js` - Microsoft Graph integration
- `lib/oauth2-apps.js` - OAuth2 application configurations
- `lib/export.js` - Export class for bulk email export operations
- `lib/api-routes/export-routes.js` - Export REST API endpoints
- `workers/api.js` - REST API worker with Hapi server
- `lib/routes-ui.js` - Web UI routes for admin interface

## Technology Stack

- **Runtime**: Node.js >=20.x with Worker Threads
- **API Framework**: Hapi.js
- **Database**: Redis (ioredis) + BullMQ for job queues
- **Email**: ImapFlow (IMAP), Nodemailer (SMTP)
- **OAuth2**: Gmail API, Microsoft Graph, Mail.ru

## Development Commands

```
npm start         # Production mode
npm run dev       # Development mode (verbose logging, Redis DB 9)
npm test          # Run full test suite (lint + tests)
npm run format    # Format code with Prettier
npm run format:check  # Check formatting without changes
npm run lint      # Lint with ESLint
npm run swagger   # Generate OpenAPI docs
npm run single    # Single-worker debug mode with Inspector
```

## Testing

- Uses Node.js native test runner with native assert module
- Tests run via Grunt: `npm test` executes `grunt` which runs Node.js test runner
- Tests located in `/test` directory
- Uses Redis database 9 for test isolation
- Run `npm test` for full test suite with linting

## Main Process (server.js)

The main process orchestrates all worker threads and manages system lifecycle:

**Responsibilities:**
- Spawns and monitors worker threads (health checks every 5s via heartbeats)
- Assigns email accounts to IMAP workers using load-balanced round-robin
- Routes inter-thread RPC calls with configurable timeout (`EENGINE_TIMEOUT`, default: 10s)
- Manages Redis connection and monitors latency
- Handles license validation (checks every 20 minutes, 28-day grace period)
- Collects Prometheus metrics from all workers

**Startup sequence:**
1. Load license from file/environment/Redis
2. Initialize settings (secrets, passwords, service ID)
3. Start API worker (wait for ready)
4. Start all IMAP workers (wait for ready)
5. Assign accounts to IMAP workers
6. Start webhooks, submit, documents workers
7. Start optional SMTP/IMAP proxy servers if enabled

**Account assignment:**
- Initial: Round-robin with load awareness (accounts per worker = ceil(total/workers))
- Reassignment after crashes: Rendezvous hashing for consistent routing
- Failsafe: 10-second timeout ensures orphaned accounts get reassigned

**Key functions:**
- `spawnWorker(type)` - Create worker thread
- `assignAccounts()` - Distribute accounts to IMAP workers
- `call(worker, message)` - RPC with timeout
- `checkWorkerHealth()` - Monitor heartbeats, auto-restart unresponsive workers

## Workers

EmailEngine uses Node.js Worker Threads for isolated execution. Workers communicate via message passing with the main thread (`server.js`).

| Worker | File | Count | Purpose |
|--------|------|-------|---------|
| API | `api.js` | 1 | HTTP server for REST API and admin UI (see API Worker section below) |
| IMAP | `imap.js` | 4* | Email sync engine (see IMAP Worker section below) |
| Webhooks | `webhooks.js` | 1* | Webhook delivery processor (see Webhooks section below) |
| Submit | `submit.js` | 1* | Email delivery processor (see Submit Worker section below) |
| Export | `export.js` | 1* | Account data export processor (see Export Worker section below) |
| Documents | `documents.js` | 1 | **Deprecated.** Indexes emails in Elasticsearch (legacy feature) |
| SMTP | `smtp.js` | 1 | Optional SMTP server (see SMTP Server section below) |
| IMAP Proxy | `imap-proxy.js` | 1 | Optional IMAP proxy server (see IMAP Proxy section below) |

*Configurable via environment variables (`EENGINE_WORKERS`, `EENGINE_WORKERS_WEBHOOKS`, `EENGINE_WORKERS_SUBMIT`, `EENGINE_EXPORT_QC`)

**Worker Lifecycle:**
- Main thread spawns workers at startup and monitors health via heartbeats (every 10s)
- IMAP workers receive account assignments from main thread
- Workers auto-restart on crash; accounts are reassigned to available workers
- BullMQ queues distribute jobs to webhooks, submit, and documents workers

### API Worker

The API worker (`workers/api.js`) runs a Hapi.js HTTP server serving both the REST API (`/v1/*`) and admin web UI (`/admin/*`).

**Server features:**
- REST API with OpenAPI/Swagger documentation (`/admin/swagger`)
- Admin dashboard with Handlebars templates
- Server-Sent Events (SSE) for real-time account updates (`/admin/changes`)
- Static file serving, CSRF protection, i18n support (7 languages)

**Authentication:**
- **API tokens**: Bearer token via `Authorization` header or `?access_token=` query param
- **Sessions**: Cookie-based (`ee` cookie) for admin UI
- **OAuth2**: Optional OKTA integration (`OKTA_OAUTH2_*` env vars)
- **TOTP**: Optional two-factor authentication for admin login

**Token scopes:** `api`, `metrics`, `smtp`, `imap-proxy`, `*` (all)

**API route categories:**
- `/v1/account/{account}/*` - Account and message operations
- `/v1/token*` - API token management
- `/v1/settings` - Global configuration
- `/v1/oauth2*` - OAuth2 app management
- `/v1/webhooks*`, `/v1/templates*`, `/v1/gateways*` - Resources

**Configuration:**
- `EENGINE_PORT` / `PORT` - Listen port (default: 3000)
- `EENGINE_HOST` - Bind address (default: 127.0.0.1)
- `EENGINE_MAX_BODY_SIZE` - Max POST body (default: 25MB)
- `EENGINE_TIMEOUT` - Request timeout (default: 10s), override with `X-EE-Timeout` header
- `EENGINE_API_PROXY` - Enable X-Forwarded-For parsing

**Key files:**
- `workers/api.js` - Hapi server setup and middleware
- `lib/routes-ui.js` - Admin UI routes (88 routes)
- `lib/api-routes/*.js` - REST API route modules
- `lib/tokens.js` - Token validation and CRUD

### IMAP Worker

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

**Operations supported:**
- Message: `listMessages`, `getMessage`, `getText`, `getRawMessage`, `getAttachment`
- Message actions: `updateMessage`, `moveMessage`, `deleteMessage`, `uploadMessage`
- Mailbox: `listMailboxes`, `createMailbox`, `modifyMailbox`, `deleteMailbox`
- Account: `pause`, `resume`, `delete`, `getQuota` (IMAP only)

**Error handling:**
- Auth failures tracked; auto-disable after threshold (4-hour window)
- Transient errors (timeout, DNS) trigger reconnection with backoff
- Permanent errors (5xx) fail immediately
- Excessive reconnection detection (>20/min triggers warning)

**Key files:**
- `workers/imap.js` - Worker thread with ConnectionHandler class
- `lib/email-client/imap-client.js` - IMAP implementation
- `lib/email-client/gmail-client.js` - Gmail API implementation
- `lib/email-client/outlook-client.js` - Outlook/Graph implementation
- `lib/email-client/base-client.js` - Shared client logic

**Limitations:**
- Gmail/Outlook: `getQuota` not supported
- Gmail: No IDLE equivalent (polling fallback)
- Outlook: `uploadMessage` only works for drafts

### Webhooks

The webhooks system (`workers/webhooks.js`, `lib/webhooks.js`) delivers real-time HTTP POST notifications when email events occur. Uses BullMQ queue for reliable delivery with retries.

**Supported events:**
- Message events: `messageNew`, `messageDeleted`, `messageUpdated`, `messageSent`, `messageDeliveryError`, `messageFailed`, `messageBounce`, `messageComplaint`
- Mailbox events: `mailboxNew`, `mailboxDeleted`, `mailboxReset`
- Account events: `accountAdded`, `accountInitialized`, `accountDeleted`, `authenticationError`, `authenticationSuccess`, `connectError`
- Tracking events: `trackOpen`, `trackClick`, `listUnsubscribe`, `listSubscribe`
- Export events: `exportCompleted`, `exportFailed`

**Configuration levels:**
1. Global: `webhooksEnabled`, `webhooks` (URL), `webhookEvents` (whitelist)
2. Per-account: `webhooks` URL overrides global
3. Custom routes: Multiple URLs with JavaScript filter/transform functions

**Delivery details:**
- Retries: 10 attempts with exponential backoff (starting at 5s)
- Authentication: Basic auth via URL credentials, custom headers, or HMAC-SHA256 signature
- Signature header: `X-EE-Wh-Signature` (HMAC-SHA256 of body using service secret)
- Concurrency: Configurable via `EENGINE_NOTIFY_QC` (default: 1)

**Custom routes** (`lib/webhooks.js`):
- `fn` - JavaScript filter function returning boolean (include/exclude event)
- `map` - JavaScript transform function to modify payload before delivery
- Functions run in sandboxed SubScript environment (30s timeout, 1MB max)

**Key files:**
- `workers/webhooks.js` - BullMQ worker processing webhook queue
- `lib/webhooks.js` - WebhooksHandler class for CRUD and payload formatting
- `lib/email-client/notification-handler.js` - Event emission to webhook queue

### Submit Worker

The submit worker (`workers/submit.js`) processes queued outbound emails via BullMQ and delivers them through SMTP or provider APIs (Gmail, Outlook). All email sending in EmailEngine is asynchronous.

**How it works:**
1. API/SMTP server queues message to Redis (content) + BullMQ (job metadata)
2. Submit worker picks up job from queue
3. Loads account and calls `submitMessage()` in base-client.js
4. Sends via SMTP or OAuth2 API depending on account configuration
5. Fires webhook events for success/failure

**Retry logic:**
- Default: 10 attempts (`deliveryAttempts` setting)
- Backoff: Exponential starting at 5s (`5s, 10s, 20s, 40s...`)
- Retries on transient errors (< 500 status code)
- No retry on permanent 5xx errors (message rejected)

**Webhook events:**
- `messageSent` - Message accepted by SMTP server
- `messageDeliveryError` - Retryable error occurred (includes `nextAttempt`)
- `messageFailed` - All retries exhausted, delivery failed

**Configuration:**
- `EENGINE_SUBMIT_QC` - Concurrency per worker (default: 1)
- `EENGINE_SUBMIT_DELAY` - Rate limiting (e.g., `1s` = 1 msg/sec)
- `deliveryAttempts` setting - Default retry count (default: 10)

**Post-delivery actions:**
- Uploads to Sent folder (if IMAP account, not Gmail)
- Sets `\Answered` flag on replied messages
- Sets `$Forwarded` flag on forwarded messages
- Updates gateway delivery stats (if using gateway)

**Key files:**
- `workers/submit.js` - BullMQ worker implementation
- `lib/email-client/base-client.js` - `queueMessage()` and `submitMessage()` logic
- `lib/outbox.js` - Queue inspection API

### Export Worker

The export worker (`workers/export.js`) processes bulk email export jobs via BullMQ. It extracts messages from accounts and writes them to compressed NDJSON files with optional encryption.

**How it works:**
1. API creates export job with date range and folder filters
2. Worker indexes matching messages from specified folders
3. Fetches message content in batches (parallel for API accounts, sequential for IMAP)
4. Writes to gzip-compressed NDJSON file (optionally encrypted)
5. Fires webhook events on completion or failure

**Export phases:**
- `pending` - Job queued, waiting for worker
- `indexing` - Scanning folders for matching messages
- `exporting` - Fetching and writing message content
- `complete` - Export finished successfully

**Error handling and recovery:**
- **Transient errors** (network timeouts, 5xx responses): Retry with exponential backoff
- **Skippable errors** (message not found, 404): Skip message, increment counter
- **Account validation**: Checks every 60s if account still exists
- **Resume capability**: Failed exports with progress can be resumed from checkpoint

**Resumability:**
An export is marked resumable when:
- Export made progress (`lastProcessedScore > 0`)
- Messages remain to process (`messagesExported < messagesQueued`)
- Account was not deleted during export

**Retry configuration:**
- IMAP messages: 3 retries with 2s base delay (exponential backoff)
- API batch requests: 5 retries for rate limits (429) with 5s base delay
- Folder indexing: 3 retries with 1s base delay

**Webhook events:**
- `exportCompleted` - Export finished with stats (messages exported, skipped, bytes)
- `exportFailed` - Export failed with error details and phase info

**Configuration:**
- `EENGINE_EXPORT_QC` - Concurrency per worker (default: 1)
- `EENGINE_EXPORT_TIMEOUT` - Operation timeout (default: 5 minutes)
- `EENGINE_EXPORT_PATH` - Export file directory (default: OS temp dir)
- `exportMaxAge` setting - Export file retention (default: 7 days)
- `exportMaxConcurrent` setting - Per-account concurrent limit (default: 3)
- `exportMaxGlobalConcurrent` setting - Global concurrent limit (default: 10)
- `exportMaxMessageSize` setting - Max attachment size (default: 25MB)

**API endpoints:**
- `POST /v1/account/{account}/export` - Create export job
- `GET /v1/account/{account}/export/{exportId}` - Get export status
- `GET /v1/account/{account}/export/{exportId}/download` - Download completed export
- `POST /v1/account/{account}/export/{exportId}/resume` - Resume failed export
- `DELETE /v1/account/{account}/export/{exportId}` - Cancel/delete export
- `GET /v1/account/{account}/exports` - List exports with pagination

**Key files:**
- `workers/export.js` - BullMQ worker implementation
- `lib/export.js` - Export class with CRUD and queue operations
- `lib/api-routes/export-routes.js` - REST API endpoints

### SMTP Server

The SMTP server (`workers/smtp.js`) is a built-in Message Submission Agent (MSA) that allows legacy applications to send emails through EmailEngine using standard SMTP protocol. Messages are queued for asynchronous delivery via the Submit worker.

**How it works:**
1. Client connects and optionally authenticates via SMTP AUTH
2. Client sends message with MAIL FROM, RCPT TO, and DATA commands
3. Server queues message for delivery through the associated EmailEngine account
4. Returns queue ID and scheduled send time

**Authentication methods:**
- With auth enabled (`smtpServerAuthEnabled`):
  - Username: Account ID
  - Password: Global password (`smtpServerPassword`) or 64-char hex token with `smtp` scope
- Without auth: Specify account via `X-EE-Account` header in message

**Configuration** (settings or environment variables):
- `smtpServerEnabled` / `EENGINE_SMTP_ENABLED` - Enable the server
- `smtpServerPort` / `EENGINE_SMTP_PORT` - Listen port (default: 2525)
- `smtpServerHost` / `EENGINE_SMTP_HOST` - Bind address (default: 127.0.0.1)
- `smtpServerAuthEnabled` - Require SMTP authentication
- `smtpServerPassword` / `EENGINE_SMTP_SECRET` - Global password (encrypted)
- `smtpServerTLSEnabled` - Enable TLS encryption
- `smtpServerProxy` / `EENGINE_SMTP_PROXY` - Enable PROXY protocol (HAProxy)

**Special headers** (removed before sending):
- `X-EE-Account` - Specify sending account (when auth disabled)
- `X-EE-Idempotency-Key` - Prevent duplicate submissions

**Limitations:**
- Max message size: 25MB (configurable via `EENGINE_MAX_SMTP_MESSAGE_SIZE`)
- Asynchronous delivery only (messages queued, not sent immediately)
- Account must have valid SMTP or OAuth2 credentials configured

### IMAP Proxy

The IMAP proxy (`lib/imapproxy/`) allows standard IMAP clients to access EmailEngine-managed accounts. It abstracts OAuth2 complexity, enabling legacy clients to connect to Gmail, Microsoft 365, and other OAuth2-only providers.

**How it works:**
1. Client connects and authenticates with account ID + password/token
2. Proxy validates credentials and establishes connection to real mail server
3. After auth, all IMAP commands pass through transparently to backend

**Authentication methods:**
- Global password: Configure `imapProxyServerPassword` setting
- Access tokens: 64-character hex token with `imap-proxy` or `*` scope

**Configuration** (settings or environment variables):
- `imapProxyServerEnabled` / `EENGINE_IMAP_PROXY_ENABLED` - Enable the proxy
- `imapProxyServerPort` / `EENGINE_IMAP_PROXY_PORT` - Listen port (default: 2993)
- `imapProxyServerHost` / `EENGINE_IMAP_PROXY_HOST` - Bind address
- `imapProxyServerTLSEnabled` - Enable TLS encryption
- `imapProxyServerProxy` - Enable PROXY protocol (HAProxy)

**Key files:**
- `lib/imapproxy/imap-server.js` - Main proxy server and authentication logic
- `lib/imapproxy/imap-core/` - IMAP protocol implementation (RFC 3501)

**Limitations:**
- Does not work with API-only accounts (e.g., Mail.ru API mode)
- Requires IMAP support on the email provider

## Architecture Notes

- **Multi-threaded**: 8 worker types (API, IMAP, webhooks, submit, export, documents, SMTP server, IMAP proxy)
- **Redis-backed**: Primary data store with Lua scripts for atomic operations
- **Encrypted**: All credentials encrypted at rest (AES-256-GCM)
- **State machine**: Account states (init, connecting, syncing, connected, authenticationError, connectError, unset)

## Environment Variables

**Core:**
- `EENGINE_REDIS` / `REDIS_URL` - Redis connection URI (default: `redis://127.0.0.1:6379/8`)
- `EENGINE_PORT` / `PORT` - API server port (default: 3000)
- `EENGINE_HOST` - API server bind address (default: 127.0.0.1)
- `EENGINE_TIMEOUT` - Command timeout in ms (default: 10000)
- `EENGINE_LOG_LEVEL` - Logging level (default: trace)

**Workers:**
- `EENGINE_WORKERS` - IMAP worker count (default: 4)
- `EENGINE_WORKERS_WEBHOOKS` - Webhook worker count (default: 1)
- `EENGINE_WORKERS_SUBMIT` - Submit worker count (default: 1)
- `EENGINE_EXPORT_QC` - Export concurrency per worker (default: 1)
- `EENGINE_EXPORT_TIMEOUT` - Export operation timeout (default: 5 minutes)
- `EENGINE_NOTIFY_QC` - Webhook concurrency per worker (default: 1)

**Prepared configuration** (applied on startup):
- `EENGINE_SETTINGS` - JSON settings object
- `EENGINE_PREPARED_TOKEN` - Base64url msgpack-encoded API token
- `EENGINE_PREPARED_PASSWORD` - Base64url PBKDF2 password hash
- `EENGINE_PREPARED_LICENSE` - License key

## Code Style Rules

- Never use emojis in code or documentation, only printable ASCII characters
- When composing git commit messages do not include Claude as co-contributor
- After making code changes, run `npm run format` and `npm run lint` before committing
