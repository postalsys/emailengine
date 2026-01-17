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
- `/workers` - Worker thread modules (7 worker types, see Workers section)
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
| API | `api.js` | 1 | REST API server (Hapi.js), handles all HTTP requests |
| IMAP | `imap.js` | 4* | Email sync engine, manages IMAP/Gmail/Outlook connections per account |
| Webhooks | `webhooks.js` | 1* | Webhook delivery processor (see Webhooks section below) |
| Submit | `submit.js` | 1* | Processes queued emails for SMTP submission |
| Documents | `documents.js` | 1 | **Deprecated.** Indexes emails in Elasticsearch (legacy feature) |
| SMTP | `smtp.js` | 1 | Optional SMTP server (see SMTP Server section below) |
| IMAP Proxy | `imap-proxy.js` | 1 | Optional IMAP proxy server (see IMAP Proxy section below) |

*Configurable via environment variables (`EENGINE_WORKERS`, `EENGINE_WORKERS_WEBHOOKS`, `EENGINE_WORKERS_SUBMIT`)

**Worker Lifecycle:**
- Main thread spawns workers at startup and monitors health via heartbeats (every 10s)
- IMAP workers receive account assignments from main thread
- Workers auto-restart on crash; accounts are reassigned to available workers
- BullMQ queues distribute jobs to webhooks, submit, and documents workers

### Webhooks

The webhooks system (`workers/webhooks.js`, `lib/webhooks.js`) delivers real-time HTTP POST notifications when email events occur. Uses BullMQ queue for reliable delivery with retries.

**Supported events:**
- Message events: `messageNew`, `messageDeleted`, `messageUpdated`, `messageSent`, `messageDeliveryError`, `messageFailed`, `messageBounce`, `messageComplaint`
- Mailbox events: `mailboxNew`, `mailboxDeleted`, `mailboxReset`
- Account events: `accountAdded`, `accountInitialized`, `accountDeleted`, `authenticationError`, `authenticationSuccess`, `connectError`
- Tracking events: `trackOpen`, `trackClick`, `listUnsubscribe`, `listSubscribe`

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

- **Multi-threaded**: 7 worker types (API, IMAP, webhooks, submit, documents, SMTP server, IMAP proxy)
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
