# Claude Development Guidelines

## Project Overview

EmailEngine is an email sync platform that provides REST API access to email accounts. It supports IMAP/SMTP, Gmail API, and Microsoft Graph (Outlook) with real-time webhooks for email events.

## Project Structure

- `server.js` - Main entry point, manages worker threads and lifecycle
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

## Workers

EmailEngine uses Node.js Worker Threads for isolated execution. Workers communicate via message passing with the main thread (`server.js`).

| Worker | File | Count | Purpose |
|--------|------|-------|---------|
| API | `api.js` | 1 | REST API server (Hapi.js), handles all HTTP requests |
| IMAP | `imap.js` | 4* | Email sync engine, manages IMAP/Gmail/Outlook connections per account |
| Webhooks | `webhooks.js` | 1* | Delivers webhook notifications for email events |
| Submit | `submit.js` | 1* | Processes queued emails for SMTP submission |
| Documents | `documents.js` | 1 | **Deprecated.** Indexes emails in Elasticsearch (legacy feature) |
| SMTP | `smtp.js` | 1 | Optional SMTP server for local email submission (port 2525) |
| IMAP Proxy | `imap-proxy.js` | 1 | Optional IMAP proxy server (see IMAP Proxy section below) |

*Configurable via environment variables (`EENGINE_WORKERS`, `EENGINE_WORKERS_WEBHOOKS`, `EENGINE_WORKERS_SUBMIT`)

**Worker Lifecycle:**
- Main thread spawns workers at startup and monitors health via heartbeats (every 10s)
- IMAP workers receive account assignments from main thread
- Workers auto-restart on crash; accounts are reassigned to available workers
- BullMQ queues distribute jobs to webhooks, submit, and documents workers

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

## Code Style Rules

- Never use emojis in code or documentation, only printable ASCII characters
- When composing git commit messages do not include Claude as co-contributor
- After making code changes, run `npm run format` and `npm run lint` before committing
