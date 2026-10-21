# Environment variables

Every `EENGINE_*` variable EmailEngine reads. Most have a matching command line option and
configuration file key (see `config/default.toml`); the environment variable wins over both.

Any variable can also be read from a file: set `<NAME>_FILE` to the path of a file holding the
value (the Docker and Kubernetes secrets convention). Surrounding whitespace in the file is
trimmed, and a variable set directly wins over its `_FILE` form.

Durations take a number with a unit (`30s`, `10m`, `1h`, `7d`) or plain milliseconds unless the
entry says otherwise. Sizes take a number with a unit (`5MB`, `1GB`) or plain bytes.

`test/env-docs-guardrail-test.js` fails when the code reads a variable this file does not list.

## Core

| Variable                          | Default                    | Description                                                                                                                        |
| --------------------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `EENGINE_REDIS`                   | `redis://127.0.0.1:6379/8` | Redis connection URI. `REDIS_URL` is read when this is unset.                                                                      |
| `EENGINE_REDIS_PREFIX`            | none                       | Prefix for every Redis key, so several instances can share one database.                                                           |
| `EENGINE_SECRET`                  | none                       | Encryption secret for stored credentials. Changing it makes stored credentials unreadable; use `emailengine encrypt` to rotate.    |
| `EENGINE_PORT`                    | `3000`                     | API and admin UI port. `PORT` is read when this is unset.                                                                          |
| `EENGINE_HOST`                    | `127.0.0.1`                | API and admin UI bind address.                                                                                                     |
| `EENGINE_TIMEOUT`                 | `10s`                      | How long an API request waits for a worker to answer (duration).                                                                   |
| `EENGINE_LOG_LEVEL`               | `trace`                    | Logging level.                                                                                                                     |
| `EENGINE_LOG_RAW`                 | `false`                    | Log raw IMAP and SMTP protocol traffic. Credentials are masked either way.                                                         |
| `EENGINE_SETTINGS`                | none                       | JSON object of settings, re-applied on every start. A value saved in the admin UI for one of its keys reverts at the next restart. |
| `EENGINE_PREPARED_TOKEN`          | none                       | A base64url msgpack-encoded API token to provision at start.                                                                       |
| `EENGINE_PREPARED_PASSWORD`       | none                       | A base64url PBKDF2 admin password hash to apply at start. Writing a different hash ends every admin session.                       |
| `EENGINE_PREPARED_LICENSE`        | none                       | A license key to apply at start.                                                                                                   |
| `EENGINE_REQUIRE_API_AUTH`        | none                       | Initial value for whether API requests need an access token (`true`/`false`), used when the setting has never been saved.          |
| `EENGINE_ENABLE_OAUTH_TOKENS_API` | none                       | Initial value for the setting that allows the OAuth2 access token API, used when it has never been saved.                          |
| `EENGINE_CONNECTION_SETUP_DELAY`  | `0`                        | Pause between two account assignments while accounts are handed to workers, to spread the connection load at start (duration).     |
| `EENGINE_UPDATE_CHECK_DISABLED`   | `false`                    | Stop checking for new EmailEngine releases.                                                                                        |
| `EENGINE_BEACON_DISABLED`         | `false`                    | Opt out of the anonymized feature-usage diagnostics sent with license validation. License validation itself is unaffected.         |
| `EENGINE_DISABLE_SETUP_WARNINGS`  | `false`                    | Hide the setup warning banners in the admin UI.                                                                                    |
| `EENGINE_DOCEAN`                  | none                       | Set by the DigitalOcean one-click image; adjusts the dashboard and diagnostics. Not for manual use.                                |
| `EENGINE_INSTALL_SCRIPT`          | none                       | Set by the install script; adjusts the dashboard and diagnostics. Not for manual use.                                              |

## Workers and queues

| Variable                                 | Default                    | Description                                                                                                                                             |
| ---------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EENGINE_WORKERS`                        | `4`                        | IMAP worker threads.                                                                                                                                    |
| `EENGINE_WORKERS_API`                    | `1`                        | API worker threads. Values above 1 need `SO_REUSEPORT` (Linux) and fall back to 1 elsewhere.                                                            |
| `EENGINE_WORKERS_WEBHOOKS`               | `1`                        | Webhook worker threads.                                                                                                                                 |
| `EENGINE_WORKERS_SUBMIT`                 | `1`                        | Submit (outgoing mail) worker threads.                                                                                                                  |
| `EENGINE_WORKERS_EXPORT`                 | `1`                        | Export worker threads.                                                                                                                                  |
| `EENGINE_NOTIFY_QC`                      | `1`                        | Webhook deliveries each webhook worker runs at once.                                                                                                    |
| `EENGINE_SUBMIT_QC`                      | `1`                        | Messages each submit worker sends at once.                                                                                                              |
| `EENGINE_SUBMIT_DELAY`                   | none                       | Minimum delay between two messages from one submit worker (duration).                                                                                   |
| `EENGINE_EXPORT_QC`                      | `1`                        | Exports each export worker runs at once.                                                                                                                |
| `EENGINE_EXPORT_TIMEOUT`                 | `5m`                       | Timeout of a single export operation (duration).                                                                                                        |
| `EENGINE_EXPORT_PATH`                    | system temporary directory | Where export files are written.                                                                                                                         |
| `EENGINE_EXPORT_MAX_AGE`                 | `86400000`                 | How long a finished export is kept, in milliseconds. The `exportMaxAge` setting wins when set.                                                          |
| `EENGINE_QUEUE_REMOVE_AFTER`             | `0`                        | Initial value for the `queueKeep` setting: completed queue entries to retain.                                                                           |
| `EENGINE_QUEUE_KEEP_FAILED`              | `500`                      | Failed queue entries retained per queue, at least. Overrides the `queueKeepFailed` setting.                                                             |
| `EENGINE_QUEUE_KEEP_FAILED_AGE`          | `604800`                   | How long failed queue entries are retained, in seconds. Overrides the `queueKeepFailedAge` setting.                                                     |
| `EENGINE_QUEUE_KEEP_FAILED_CONTENT`      | `100`                      | How many of the most recent failed messages keep their content so they can be retried (`0` keeps none). Overrides the `queueKeepFailedContent` setting. |
| `EENGINE_QUEUE_KEEP_FAILED_CONTENT_SIZE` | `100MB`                    | Total size of the retained failed-message content (size). Overrides the `queueKeepFailedContentSize` setting.                                           |

## Mail synchronization

| Variable                                 | Default          | Description                                                                                                                                                                      |
| ---------------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EENGINE_FETCH_BATCH_SIZE`               | `1000`           | Messages fetched per IMAP FETCH command during a sync.                                                                                                                           |
| `EENGINE_CHUNK_SIZE`                     | `1000000`        | Chunk size for streaming attachment and message downloads (size).                                                                                                                |
| `EENGINE_IMAP_SOCKET_TIMEOUT`            | ImapFlow default | Inactivity timeout of IMAP connections (duration).                                                                                                                               |
| `EENGINE_DISABLE_COMPRESSION`            | `false`          | Do not negotiate IMAP COMPRESS=DEFLATE.                                                                                                                                          |
| `EENGINE_IMAP_STALE_CHECK_INTERVAL`      | disabled         | Quiet period after which a resync checks the main mailbox over the command connection and reconnects an account whose primary connection stopped seeing new messages (duration). |
| `EENGINE_MAX_IMAP_AUTH_FAILURE_TIME`     | `3d`             | How long authentication may keep failing before syncing is switched off for the account (duration).                                                                              |
| `EENGINE_GMAIL_FALLBACK_POLL_INTERVAL`   | `10m`            | How often a Gmail API account polls for changes when no Pub/Sub notification arrives (duration, or plain milliseconds).                                                          |
| `EENGINE_OUTLOOK_FALLBACK_POLL_INTERVAL` | `10m`            | How often each MS Graph account runs a missed-notification recovery pass (duration, `0` disables, never below 10 seconds).                                                       |
| `EENGINE_FETCH_TIMEOUT`                  | `90000`          | Response timeout of outbound HTTP requests made through the shared dispatchers (provider APIs, OAuth2, attachments given by URL), in milliseconds.                               |

## API and admin UI

| Variable                          | Default   | Description                                                                                                                                              |
| --------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EENGINE_API_PROXY`               | `false`   | Trust `X-Forwarded-For` from a reverse proxy. The Docker image sets it to `true`.                                                                        |
| `EENGINE_API_PROXY_ADDRESSES`     | none      | IPs or CIDRs of the proxies allowed to set `X-Forwarded-For`. Set it whenever you rely on the admin address allowlist or per-token address restrictions. |
| `EENGINE_ADMIN_ACCESS_ADDRESSES`  | none      | IPs or CIDRs allowed to reach `/admin`.                                                                                                                  |
| `EENGINE_CORS_ORIGIN`             | none      | Allowed CORS origins, space separated (`*` for any). CORS is off while unset.                                                                            |
| `EENGINE_CORS_MAX_AGE`            | `60`      | How long browsers may cache a CORS preflight answer, in seconds.                                                                                         |
| `EENGINE_MAX_SIZE`                | `5MB`     | Largest attachment accepted in an API request (size).                                                                                                    |
| `EENGINE_MAX_BODY_SIZE`           | `50MB`    | Largest API request body (size).                                                                                                                         |
| `EENGINE_MAX_PAYLOAD_TIMEOUT`     | `10s`     | How long an API request body may take to arrive (duration).                                                                                              |
| `EENGINE_CSP_MODE`                | `enforce` | How the Content-Security-Policy is delivered: `enforce`, `report-only` or `off`.                                                                         |
| `EENGINE_DISABLE_MESSAGE_BROWSER` | `false`   | Remove the message browser from the account pages.                                                                                                       |
| `EENGINE_MCP_ENABLED`             | `true`    | Register the MCP endpoint routes. The `mcpEnabled` setting is the runtime switch.                                                                        |
| `EENGINE_TOKEN_LOG_ENTRIES`       | `1000`    | Requests retained per access token in the audit log. Overrides the `tokenLogEntries` setting.                                                            |
| `EENGINE_TOKEN_LOG_AGE`           | `604800`  | How long a token's audit log survives its last use, in seconds. Overrides the `tokenLogAge` setting.                                                     |
| `EENGINE_DISABLE_THREAD_COLLAPSE` | `false`   | Stop web-safe HTML from folding quoted thread history into a collapsed block. Overrides the `disableThreadCollapse` setting.                             |

## Webhooks and outbound HTTP

| Variable                        | Default                    | Description                                                                                                                                           |
| ------------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EENGINE_WEBHOOK_TIMEOUT`       | `30s`                      | Wall-clock cap on one webhook delivery attempt (duration).                                                                                            |
| `EENGINE_WEBHOOK_EGRESS_POLICY` | `link-local`               | Where webhook deliveries and autodiscovery lookups may connect: `link-local`, `private` or `off`.                                                     |
| `EENGINE_HTTP_PROXY_ENABLED`    | none                       | Overrides the `httpProxyEnabled` setting (the dedicated proxy for outbound HTTP). `false` keeps HTTP direct while IMAP and SMTP use the global proxy. |
| `EENGINE_HTTP_PROXY_URL`        | none                       | Overrides the `httpProxyUrl` setting.                                                                                                                 |
| `EENGINE_GCP_METADATA_HOST`     | `metadata.google.internal` | Where a Cloud Pub/Sub app using the attached service account reaches the metadata server (`host`, `host:port` or `http://host[:port]`).               |

## Built-in SMTP server and IMAP proxy

The `EENGINE_SMTP_ENABLED`, `_SECRET`, `_PORT`, `_HOST` and `_PROXY` variables are deprecated and
will be removed after 2027-01-01; configure the SMTP server in the admin UI or through the settings
API instead. All of these only seed the setting while it has never been saved.

| Variable                        | Default     | Description                                                       |
| ------------------------------- | ----------- | ----------------------------------------------------------------- |
| `EENGINE_SMTP_ENABLED`          | `false`     | Initial value for `smtpServerEnabled`. Deprecated.                |
| `EENGINE_SMTP_SECRET`           | none        | Initial value for `smtpServerPassword`. Deprecated.               |
| `EENGINE_SMTP_PORT`             | `2525`      | Initial value for `smtpServerPort`. Deprecated.                   |
| `EENGINE_SMTP_HOST`             | `127.0.0.1` | Initial value for `smtpServerHost`. Deprecated.                   |
| `EENGINE_SMTP_PROXY`            | `false`     | Initial value for `smtpServerProxy` (PROXY protocol). Deprecated. |
| `EENGINE_SMTP_MAX_CLIENTS`      | `100`       | Maximum concurrent SMTP server connections.                       |
| `EENGINE_MAX_SMTP_MESSAGE_SIZE` | `25MB`      | Largest message the SMTP server accepts (size).                   |
| `EENGINE_IMAP_PROXY_ENABLED`    | `false`     | Initial value for `imapProxyServerEnabled`.                       |
| `EENGINE_IMAP_PROXY_SECRET`     | none        | Initial value for `imapProxyServerPassword`.                      |
| `EENGINE_IMAP_PROXY_PORT`       | `2993`      | Initial value for `imapProxyServerPort`.                          |
| `EENGINE_IMAP_PROXY_HOST`       | `127.0.0.1` | Initial value for `imapProxyServerHost`.                          |
| `EENGINE_IMAP_PROXY_PROXY`      | `false`     | Initial value for `imapProxyServerProxy` (PROXY protocol).        |
| `EENGINE_IMAPPROXY_MAX_CLIENTS` | `1000`      | Maximum concurrent IMAP proxy connections.                        |

## TLS

| Variable                     | Default                  | Description                                                                                                                                                                                                                                                               |
| ---------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EENGINE_API_TLS`            | `false`                  | Serve the API and admin UI over HTTPS.                                                                                                                                                                                                                                    |
| `EENGINE_API_TLS_*`          | none                     | TLS material and options for the API listener: `_CERT`, `_KEY`, `_CA`, `_DHPARAM`, `_PASSPHRASE`, `_CIPHERS`, `_ECDH_CURVE`, `_MIN_VERSION`, `_MAX_VERSION`, `_REJECT_UNAUTHORIZED`, `_REQUEST_CERT`. Material given here outranks every certificate EmailEngine manages. |
| `EENGINE_SMTP_TLS_*`         | none                     | The same names for the SMTP server.                                                                                                                                                                                                                                       |
| `EENGINE_IMAPPROXY_TLS_*`    | none                     | The same names for the IMAP proxy.                                                                                                                                                                                                                                        |
| `EENGINE_TLS_MIN_VERSION`    | `TLSv1`                  | Oldest TLS version accepted when connecting to mail servers.                                                                                                                                                                                                              |
| `EENGINE_TLS_MIN_DH_SIZE`    | `1024`                   | Smallest Diffie-Hellman key accepted from mail servers.                                                                                                                                                                                                                   |
| `EENGINE_TLS_CIPHERS`        | `DEFAULT@SECLEVEL=0`     | Cipher list for connections to mail servers.                                                                                                                                                                                                                              |
| `EENGINE_ACME_DIRECTORY_URL` | Let's Encrypt production | ACME directory certificates are ordered from. Override together with `EENGINE_ACME_ENVIRONMENT`.                                                                                                                                                                          |
| `EENGINE_ACME_ENVIRONMENT`   | `emailengine`            | Name of the stored ACME account record. Override together with `EENGINE_ACME_DIRECTORY_URL`.                                                                                                                                                                              |
