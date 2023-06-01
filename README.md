![logo](https://raw.githubusercontent.com/postalsys/emailengine/master/static/logo/EmailEngine_logo_vert.png)

# EmailEngine Email API

Headless email client application that makes IMAP and SMTP resources available over REST. Integrate email accounts with your service with ease!

-   Documentation and details: [EmailEngine.app](https://emailengine.app/)
-   [Discord](https://emailengine.app/discord) chat room

## Use cases

-   Syncing users' emails to your service and sending out emails on behalf of your users
-   Integrating your app with a specific email account, eg. your support email
-   [Monitor INBOX and Junk folders](https://docs.emailengine.app/measuging-inbox-spam-placement/) of a test email account to see where the emails you send out end up in
-   Lightweight webmail and mobile email apps that do not want to process IMAP and MIME

## Quickstart

-   [Set-up instructions](https://emailengine.app/set-up)

## Screenshots

![](https://cldup.com/dC_4_suWrh.png)

![](https://cldup.com/KibGXRw8Mm.png)

![](https://cldup.com/mCxzWWjcLL.png)

## Version and license

Run the following command to see the version and license information both for EmailEngine and for the included modules.

```
$ emailengine license
```

## Requirements

-   **Redis** – any version

There is no official [Redis](https://redis.io/) release for Windows but you can use an alternative like [Memurai](https://www.memurai.com/).

> **Tip!** Try to keep the latency between EmailEngine and Redis as low as possible, best if these would run in the same machine or at least in the same DC. EmailEngine runs a separate Redis command for each message in a folder when syncing messages, so if the latency is not low then it takes a long time to sync a folder with a lot of messages,

## Documentation

-   [API Reference](https://api.emailengine.app/)
-   [Blog posts](https://docs.emailengine.app/tag/email-engine/)
-   For Postman you can import OpenAPI specification [here](https://api.emailengine.app/swagger.json).

## Configuring EmailEngine

See the documentation for configuring EmailEngine [here](https://emailengine.app/configuration).

## App access

By default EmailEngine allows connections only from localhost. To change this either edit config file or use `--api.host="0.0.0.0"` cli option. This would enable outside access, so you should use firewall or a proxy to only allow trusted sources.

## Deployment

### Ubuntu or Debian

You can use the included install script to set up

-   EmailEngine as a SystemD service
-   Caddy as a reverse proxy and HTTPS certificate handler

```
$ wget https://raw.githubusercontent.com/postalsys/emailengine/master/install.sh
$ chmod +x install.sh
$ ./install.sh example.com
```

Where

-   **example.com** is the domain name for EmailEngine

> **NB!** Tested with Ubuntu 20.04 and Debian 11. Might not work with other OS versions.

### SystemD

Read about running EmailEngine as a SystemD service [here](https://emailengine.app/system-d-service)

### Docker

![Docker Image Size (tag)](https://img.shields.io/docker/image-size/postalsys/emailengine/v2?label=Docker%20image%20size)

See the documentation for using EmailEngine with Docker [here](https://emailengine.app/docker).

## Resolving issues with Redis

EmailEngine is using Redis as it's data store. Redis stores everything in RAM so if something weird happens, EmailEngine could flood Redis and make the app unusable once there is no available space left.

First thing to do is to check what is actually going on. EmailEngine provides a few tools for that:

1. Check Bull queues in Redis. You can use the built in Bull Arena UI to view the state of the queues. Open [http://127.0.0.1:3000/admin/arena](http://127.0.0.1:3000/admin/arena) in your browser to see the queues.
2. Scan the used keyspace. EmailEngine provides a tool that groups keys by type. Run it like this (use the same config for DB as you are using for the main app):

```
$ emailengine scan > keyspace.csv
```

## Monitoring

There is a Prometheus output available at `/metrics` URL path of the app.

## Log analysis

Read about logging options [here](https://emailengine.app/logging)

To start EmailEngine to trail the IMAP traffic of a specific account

```
$ npm run raw -- --filter.account=account1
```

## Security and Data compliance

[Read here](https://docs.emailengine.app/data-compliance/).

## Licensing

Licensed under the commercial [EmailEngine License](./LICENSE_EMAILENGINE.txt).
