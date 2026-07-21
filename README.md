![EmailEngine Logo](https://raw.githubusercontent.com/postalsys/emailengine/master/static/logo/EmailEngine_logo_vert.png)

# EmailEngine Email API

A headless email client application that provides access to IMAP, SMTP, Gmail API, and MS Graph API resources via a unified REST API. Easily integrate email accounts with your service!

-   Full documentation: [learn.emailengine.app](https://learn.emailengine.app/)

> [!WARNING]
> EmailEngine is not free open-source software. It is "source available" software, meaning you can view and copy the source code, but you need a <a href="https://postalsys.com/plans">paid subscription</a> to run it beyond the free 14-day trial. Each EmailEngine instance comes with this trial, so you can test EmailEngine without any commitment.

## Use Cases

-   Sync users' emails with your service and send emails on their behalf.
-   Integrate your app with a dedicated email account, such as your support email.
-   [Monitor INBOX and Junk folders](https://learn.emailengine.app/docs/advanced/inbox-placement-testing) of a test email account to track where sent emails land.
-   Ideal for lightweight webmail and mobile email apps that prefer to avoid direct IMAP and MIME processing.

## Features

-   **One REST API for every provider.** IMAP/SMTP, the Gmail API, and Microsoft Graph are all exposed through the same endpoints, so your integration does not change when a user switches provider.
-   **Real-time webhooks.** Get notified about new, deleted, and updated messages, sent mail, delivery errors, bounces, and account state changes. Optional [custom routes](https://learn.emailengine.app/docs/webhooks/webhook-routing) filter and reshape payloads per destination.
-   **Sending.** Queued delivery with retries, stored [templates](https://learn.emailengine.app/docs/sending/templates), sending gateways, open and click tracking, unsubscribe handling, a blocklist, and bounce classification.
-   **Account onboarding.** A [hosted authentication form](https://learn.emailengine.app/docs/accounts/hosted-authentication) handles OAuth2 (Google, Microsoft) and IMAP credentials so you never touch the user's password.
-   **Bulk export.** Export an account's mail to compressed NDJSON, optionally encrypted.
-   **Protocol servers for legacy apps.** A built-in SMTP submission server (MSA) and an IMAP proxy let existing clients reach OAuth2-only mailboxes without implementing OAuth2 themselves.
-   **Admin interface.** Server-rendered dashboard with light and dark themes, an embedded API reference, queue inspection, and logs.
-   **Admin authentication.** Password, passkeys (WebAuthn), TOTP two-factor, and SSO through Okta or any OpenID Connect provider (Keycloak, Authentik, Entra ID, Google).
-   **Operations.** Prometheus metrics, structured logging, and a 7-language admin UI.

## Quickstart

-   [Setup Instructions](https://learn.emailengine.app/docs/getting-started/quick-start)

## Screenshots

![The EmailEngine dashboard, showing account, activity, and system counters](https://raw.githubusercontent.com/postalsys/emailengine/master/screenshots/dashboard.png)
![The accounts list, showing connected email accounts and their sync status](https://raw.githubusercontent.com/postalsys/emailengine/master/screenshots/accounts.png)
![The built-in API reference, listing the account endpoints](https://raw.githubusercontent.com/postalsys/emailengine/master/screenshots/api-reference.png)

## Requirements

-   **Node.js** - version 20 or newer (only when running from source; the prebuilt binaries and the Docker image bundle their own runtime)
-   **Redis** - any version

> [!IMPORTANT]
> EmailEngine uses Redis as its primary database, not as a cache. Set `maxmemory-policy` to `noeviction` and give Redis enough memory for your workload - with any other policy Redis can drop sync state, which makes already-synced messages look new and generates duplicate webhooks.
>
> Redis Cluster and Amazon ElastiCache are **not** supported. Use a standard Redis primary instance. EmailEngine warns about all of the above on the dashboard when it detects them.

> [!NOTE]
> While Redis does not officially support Windows, alternatives like [Memurai](https://www.memurai.com/) are available.

> [!TIP]
> Minimize the latency between EmailEngine and Redis by running both on the same machine or in the same data center. Since EmailEngine runs a separate Redis command for each message in a folder during syncing, high latency can lead to slow sync times for folders with many messages.

## Documentation

-   [Documentation](https://learn.emailengine.app/)
-   [API Reference](https://learn.emailengine.app/docs/api/emailengine-api)
-   OpenAPI specification for Postman and code generators: every instance serves its own at `/swagger.json`, or use the hosted copy at [emailengine.dev/swagger.json](https://emailengine.dev/swagger.json)

## Configuring EmailEngine

Refer to the [configuration documentation](https://learn.emailengine.app/docs/configuration) for details on setting up EmailEngine.

## App Access

By default, EmailEngine only allows connections from localhost. To enable external access, either edit the config file or use the CLI option `--api.host="0.0.0.0"`. Ensure to secure external access with a firewall or proxy to allow only trusted sources.

## Deployment

### Ubuntu or Debian

You can use the included install script to set up:

-   Redis as the data store
-   EmailEngine as a SystemD service
-   Caddy as a reverse proxy and HTTPS certificate handler

The script must run as root, and takes the domain name for EmailEngine as its first argument:

```bash
$ wget https://raw.githubusercontent.com/postalsys/emailengine/master/install.sh
$ chmod +x install.sh
$ sudo ./install.sh example.com
```

Pass a version as the optional second argument to install a specific release instead of the latest one. Re-running the script on an existing installation upgrades it in place, and it also installs `/opt/upgrade-emailengine.sh` for later upgrades.

### SystemD

Learn more about running EmailEngine as a SystemD service [here](https://learn.emailengine.app/docs/deployment/systemd).

### Docker

![Docker Image Size](https://img.shields.io/docker/image-size/postalsys/emailengine/v2?label=Docker%20image%20size)

To execute EmailEngine-CLI commands within a Docker container:

1. Exec into the container:

    ```bash
    $ docker exec -it <container-id> /bin/sh
    ```

2. Run commands using `./bin/emailengine.js`:

    ```bash
    $ node bin/emailengine.js <command>
    ```

For full Docker usage documentation, visit [here](https://learn.emailengine.app/docs/installation/docker). This repository also ships a `docker-compose.yml` and a longer [Docker deployment guide](./DOCKER_DEPLOYMENT.md).

## Command Line Interface

Run `emailengine help` for the full list, or `emailengine help <command>` for a single one.

| Command                    | Description                                          |
| -------------------------- | ---------------------------------------------------- |
| `emailengine`              | Start the EmailEngine server                         |
| `emailengine version`      | Show the version number                              |
| `emailengine license`      | Show the EmailEngine version and license terms       |
| `emailengine password`     | Set or reset the admin password                      |
| `emailengine tokens`       | Issue, export, and import API access tokens          |
| `emailengine encrypt`      | Manage field-level encryption for stored credentials |
| `emailengine export`       | Export account data, including credentials           |
| `emailengine scan`         | Scan the Redis keyspace and output a CSV report      |
| `emailengine check-bounce` | Analyze a bounce email and classify it               |

The license terms of the bundled third-party modules are not part of `emailengine license` - a running instance serves them at [http://127.0.0.1:3000/licenses.html](http://127.0.0.1:3000/licenses.html).

## Resolving Issues with Redis

EmailEngine relies on Redis as its data store. Redis stores everything in RAM, so if an issue arises, EmailEngine may flood Redis, rendering the app unusable if space runs out.

To diagnose problems:

1. **Check the job queues:** Use the built-in Bull Board UI to monitor queue states at [http://127.0.0.1:3000/admin/bull-board](http://127.0.0.1:3000/admin/bull-board) (requires an admin session).
2. **Scan Keyspace:** Run the following to group Redis keys by type and generate a report:

    ```bash
    $ emailengine scan > keyspace.csv
    ```

## Monitoring

EmailEngine provides Prometheus metrics at the `/metrics` URL path. The endpoint requires an access token with the `metrics` or `*` scope:

```bash
$ curl -H "Authorization: Bearer $EE_TOKEN" http://127.0.0.1:3000/metrics
```

## Log Analysis

For information on logging options, read the documentation [here](https://learn.emailengine.app/docs/advanced/logging).

To trace the IMAP traffic of a single account, open that account in the admin interface and turn on logging for it. EmailEngine then keeps a rolling log for the account, which you can read on the same page or download as a text file.

To log raw IMAP traffic for every account instead, start EmailEngine with `--log.raw=true` (or `EENGINE_LOG_RAW=true`). This is verbose and includes message content, so keep it off in production.

## Security and Data Compliance

For detailed security and data compliance information, refer to [this guide](https://learn.emailengine.app/docs/deployment/compliance).

## Licensing

EmailEngine is licensed under the commercial [EmailEngine License](./LICENSE_EMAILENGINE.txt).
