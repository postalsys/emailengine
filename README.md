![EmailEngine Logo](https://raw.githubusercontent.com/postalsys/emailengine/master/static/logo/EmailEngine_logo_vert.png)

# EmailEngine Email API

A headless email client application that provides access to IMAP, SMTP, Gmail API, and MS Graph API resources via a unified REST API. Easily integrate email accounts with your service!

-   Full documentation: [EmailEngine.app](https://emailengine.app/)

> [!WARNING]
> EmailEngine is not free open-source software. It is "source available" software, meaning you can view and copy the source code, but you need a paid subscription to run it beyond the free 14-day trial. Each EmailEngine instance comes with this trial, so you can test EmailEngine without any commitment.

## Use Cases

-   Sync users' emails with your service and send emails on their behalf.
-   Integrate your app with a dedicated email account, such as your support email.
-   [Monitor INBOX and Junk folders](https://docs.emailengine.app/measuging-inbox-spam-placement/) of a test email account to track where sent emails land.
-   Ideal for lightweight webmail and mobile email apps that prefer to avoid direct IMAP and MIME processing.

## Quickstart

-   [Setup Instructions](https://emailengine.app/set-up)

## Screenshots

![Screenshot 1](https://cldup.com/dC_4_suWrh.png)
![Screenshot 2](https://cldup.com/KibGXRw8Mm.png)
![Screenshot 3](https://cldup.com/mCxzWWjcLL.png)

## Version and License

Run the following command to check the version and license information for both EmailEngine and its included modules:

```bash
$ emailengine license
```

## Requirements

-   **Redis** – Any version

> [!NOTE]
> While Redis does not officially support Windows, alternatives like [Memurai](https://www.memurai.com/) are available.

> [!TIP]
> Minimize the latency between EmailEngine and Redis by running both on the same machine or in the same data center. Since EmailEngine runs a separate Redis command for each message in a folder during syncing, high latency can lead to slow sync times for folders with many messages.

## Documentation

-   [API Reference](https://api.emailengine.app/)
-   [Blog Posts](https://docs.emailengine.app/tag/email-engine/)
-   OpenAPI specification for Postman: [Swagger.json](https://api.emailengine.app/swagger.json)

## Configuring EmailEngine

Refer to the [configuration documentation](https://emailengine.app/configuration) for details on setting up EmailEngine.

## App Access

By default, EmailEngine only allows connections from localhost. To enable external access, either edit the config file or use the CLI option `--api.host="0.0.0.0"`. Ensure to secure external access with a firewall or proxy to allow only trusted sources.

## Deployment

### Ubuntu or Debian

You can use the included install script to set up:

-   EmailEngine as a SystemD service
-   Caddy as a reverse proxy and HTTPS certificate handler

```bash
$ wget https://raw.githubusercontent.com/postalsys/emailengine/master/install.sh
$ chmod +x install.sh
$ ./install.sh example.com
```

Where **example.com** is the domain name for EmailEngine.

> [!NOTE]
> Tested on Ubuntu 20.04 and Debian 11. Other versions may not be supported.

### SystemD

Learn more about running EmailEngine as a SystemD service [here](https://emailengine.app/system-d-service).

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

For full Docker usage documentation, visit [here](https://emailengine.app/docker).

## Resolving Issues with Redis

EmailEngine relies on Redis as its data store. Redis stores everything in RAM, so if an issue arises, EmailEngine may flood Redis, rendering the app unusable if space runs out.

To diagnose problems:

1. **Check Bull Queues:** Use the built-in Bull Arena UI to monitor queue states at [http://127.0.0.1:3000/admin/bull-board](http://127.0.0.1:3000/admin/bull-board).
2. **Scan Keyspace:** Run the following to group Redis keys by type and generate a report:

    ```bash
    $ emailengine scan > keyspace.csv
    ```

## Monitoring

EmailEngine provides Prometheus metrics, available at the `/metrics` URL path.

## Log Analysis

For information on logging options, read the documentation [here](https://emailengine.app/logging).

To trace IMAP traffic for a specific account, use the following command:

```bash
$ npm run raw -- --filter.account=account1
```

## Security and Data Compliance

For detailed security and data compliance information, refer to [this guide](https://docs.emailengine.app/data-compliance/).

## Licensing

EmailEngine is licensed under the commercial [EmailEngine License](./LICENSE_EMAILENGINE.txt).
