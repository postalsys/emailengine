# IMAP API

Headless email client that makes IMAP and SMTP resources available over REST. Integrate email accounts with your service with ease!

## Quickstart

1. Install Node.js and Redis
2. Install and run IMAP API

```
$ npm install -g imapapi
$ imapapi
```

3. Open [http://127.0.0.1:3000/](http://127.0.0.1:3000/) in your browser

## Use cases

-   Syncing users' emails into your service and sending out emails on behalf of your users (helpdesk software etc.)
-   Email applications (lightweight webmail and mobile apps etc. that do not want to process IMAP and MIME)

## Demo

Here's a screen recording of running and using IMAP API in action.

[![Using IMAP API](https://img.youtube.com/vi/shHZHowVnYw/0.jpg)](https://www.youtube.com/watch?v=shHZHowVnYw)

This video shows how to

1. Install and start IMAP API
2. Configure webhooks destination using the web UI (webhook handling from https://webhook.site/)
3. Create a new email account at https://ethereal.email/
4. Open Swagger documentation page that also serves as an API playground
5. Using the API playground to add a new IMAP/SMTP account using the id "example"
6. Check the webhook listing to see the notification about found messages from the added account (includes limited information)
7. Using the ID from the webhook fetch all data for the message (decoded addresses, subject, text etc, also original headers as an array)

## Licensing

Public IMAP API is licensed under AGPL. Alternative MIT-licensed version of IMAP API is available for [Postal Systems subscribers](https://postalsys.com/). You can install it as `@postalsys/imapapi` from the Postal Systems private registry.

```
$ npm install -g @postalsys/imapapi
$ imapapi
```

## Let's Go!

Make sure you have latest (at least v12.16.0) [Node.js](https://nodejs.org/api/) installed. Run IMAP API straight from NPM without downloading or installing anything manually:

```
$ npx imapapi --dbs.redis="redis://127.0.0.1:6379"
```

or when running using the MIT licensed version from [Postal Systems](https://postalsys.com/)

```
$ npx -p @postalsys/imapapi imapapi --dbs.redis="redis://127.0.0.1:6379"
```

Next open [http://127.0.0.1:3000/](http://127.0.0.1:3000/) in your browser for Web UI and documentation.

> **Tip** For human readable logs you can use _pino-pretty_ (`npm install -g pino-pretty`) by piping IMAP API output to it: `imapapi | pino-pretty`

## Documentation

-   [API Reference](https://imapapi.com/api.html)

## Features

-   IMAP API allows simple access to IMAP accounts via REST based API. No need to know IMAP or MIME internals, you get a "normal" API with paged message listings. All text (that is subjects, email addresses, text and html content etc) is utf-8. Attachments are automatically decoded to binary representation.
-   Whenever something happens on tracked accounts IMAP API posts notification over a webhook. This includes new messages, deleted messages and message flag changes.
-   No data ever leaves your system
-   Easy email sending. If you specify the message you are responding to or forwarding then IMAP API sets all required headers, updates references message's flags in IMAP and also uploads message to the Sent Mail folder after sending.
-   IMAP API is a rather thin wrapper over IMAP. This means it does not have a storage of its own. It also means that if the IMAP connection is currently not open, you get a gateway error as a result of your API request.
-   IMAP API keeps a single persistent IMAP connection open against every registered user account. To stop syncing you must remove the account from IMAP API. This is different from some webmail implementations where connections are kept open during user session only.
-   Partial text download. You can obviously download the entire rfc822 formatted raw message but it might be easier to use provided paging and message details. This also allows to specifiy maximum size for downloaded text content. Sometimes automated cron scripts etc send emails with 10+MB text so to avoid downloading that stuff IMAP API allows to set max cap size for text.
-   If you are running into IP based rate limiting then IMAP API can make use of multiple local network interfaces to make connections from different IP addresses.

## Usage

### Requirements

-   **Redis** – any version
-   **Node.js** - v12.16.0 or newer

> **NB!** Try to keep the latency between IMAP API and Redis as low as possible, best if these would run in the same machine or at least in the same DC. IMAP API runs a separate Redis command for each message in a folder when syncing messages, so if the latency is not low then it takes a long time to sync a folder with a lot of messages,

### Installation

Install dependencies

```
$ npm install --production
```

### Run

Run using [default settings](config/default.toml)

```
$ node server.js
```

Or use custom Redis connection URL

```
$ node server.js --dbs.redis="redis://127.0.0.1:6379"
```

Once application is started open http://127.0.0.1:3000/ for instructions and API documentation.

## Screenshots

**1. General overview**

![](https://cldup.com/s3Vz9pwoIi.png)

**2. Account states**

![](https://cldup.com/F2G4m3FWUT.png)

**3. Documentation**

![](https://cldup.com/foHXymkVBw.png)

**4. Settings**

![](https://cldup.com/aZj55OpeCl.png)

**5. Download stored logs**

![](https://cldup.com/AqFCHZbVvL.png)

**6. Swagger**

![](https://cldup.com/mK0aS_uVfQ.png)

## Config mapping

| Configuration option | CLI argument                         | ENV value                   | Default                      |
| -------------------- | ------------------------------------ | --------------------------- | ---------------------------- |
| IMAP Worker count    | `--workers.imap=4`                   | `WORKERS_IMAP=4`            | `4`                          |
| Redis connection URL | `--dbs.redis="url"`                  | `REDIS_URL="url"`           | `"redis://127.0.0.1:6379/8"` |
| Host to bind to      | `--api.host="1.2.3.4"`               | `API_HOST="1.2.3.4"`        | `"127.0.0.1"`                |
| Port to bind to      | `--api.port=port`                    | `API_PORT=port`             | `3000`                       |
| Max attachment size  | `--api.maxSize=5M`                   | `API_MAX_SIZE=5M`           | `5M`                         |
| Max command duration | `--service.commandTimeout=10s`       | `COMMAND_TIMEOUT=10s`       | `10s`                        |
| Log level            | `--log.level="level"`                | `LOG_LEVEL=level`           | `"trace"`                    |
| Prepared settings    | `--settings='{"JSON"}'`              | `SETTINGS='{"JSON"}'`       | not set                      |
| Encryption secret    | `--service.secret="****"`            | `IMAPAPI_SECRET="****"`     | not set                      |
| Local addresses      | `--service.localAddresses="ip1,ip2"` | `LOCAL_ADDRESSES="ip1,ip2"` | default interface            |
| API Basic Auth       | `--api.auth="user:pass"`             | `IMAPAPI_AUTH="user:pass"`  | not set                      |

> **NB!** environment variables override CLI arguments. CLI arguments override configuration file values.

If available then IMAP API uses dotenv file from project root to populate environment variables.

#### Prepared settings

If you do not want to update application settings via API calls then you can provide the initial settings via a command line option (`--settings`) or environment variable (`SETTINGS`). The value must be a valid JSON string that could be used against the `/settings` API endpoint. The behavior is identical to calling the same thing via API, so whatever settings are given are stored in the DB.

```
$ imapapi --settings='{"webhooks": "https://webhook.site/14e88aea-3391-48b2-a4e6-7b617280155d","webhookEvents":["messageNew"]}'
```

If settings object fails validation then the application does not start.

#### Encryption secret

By default account passwords are stored as cleartext in Redis. You can set an encryption secret that will be used to encrypt these passwords.

```
$ imapapi --service.secret="secret_encryption_key"
```

> **NB!** Once you have selected an encryption key you have to continue using it

Secret key only applies to new accounts or account updates. To convert existing accounts into encrypted accounts or change the encryption key you can use the ecryption tool

```
$ imapapi encrypt --service.secret="new_secret" --decrypt="old-secret"
```

This command encrypts all account passwords with `"new_secret"`. If the account password was already encrypted then uses `"old_secret"` to decrypt the encrypted values before encrypting these with the new secret.

#### Local addresses

If your server has multiple IP addresses/interfaces available then you can provide a comma separated list of these IP addresses for IMAP API to bound to when making outbound connections.

This is mostly useful if you are making a large amount of connections and might get rate limited by destination server based on your IP address. Using multiple local addresses allows to distribute separate connections between separate IP addresses. An address is selected randomly from the list whenever making a new IMAP connection.

```
$ imapapi --service.localAddresses="192.168.1.176,192.168.1.177,192.168.1.178"
```

If those interfaces aren't actually available then TCP connections will fail, so check the logs.

**Local addresses and SMTP**

By default when IMAP API is sending an email to SMTP it uses local hostname in the SMTP greeting. This hostname is resolved by `os.hostname()`. Sometimes hostname is using invalid format (eg. `Servername_local` as undersore is not actually allowed) and depending on the SMTP server it might reject such connection.

To overcome you can set the local hostname to use by appending the hostname to the IP address, separated by pipe symbol

```
$ imapapi --service.localAddresses="ip1|hostname1,ip2|hostname2,ip3|hostname3"
```

For example when using AWS you can use the private interface IP but set a public hostname.

```
$ imapapi --service.localAddresses="172.31.1.2|ec2-18-194-1-2.eu-central-1.compute.amazonaws.com"
```

So in general the hostname shoud be whatever the public interface IP (this is what the SMTP server sees) resolves to.

#### Authentication

IMAP API supports Basic Auth with a single user. This is a convenience option only, for any kind of production use you should implement your own user management and limit access with a firewall to trusted machines only.

```
$ imapapi --api.auth="user:password"
```

## API usage

> **NB!** IMAP API uses a single connection per account against the IMAP server which means that each request must finish before next one can be issued. If you pile up a bunch of requests against the same account in parallel then requests might time out before these can be actually processed.

#### 1. Set up webhook target

Open the <em>Settings</em> tab and set an URL for webhooks. Whenever something happens with any of the tracked email accounts you get a notification to this URL.

For example if flags are updated for a message you'd get a notification that looks like this:

```json
{
    "account": "example",
    "path": "[Google Mail]/All Mail",
    "event": "messageUpdated",
    "data": {
        "id": "AAAAAQAAAeE",
        "uid": 350861,
        "changes": {
            "flags": {
                "added": ["\\Seen"]
            }
        }
    }
}
```

#### 2. Register an email account with IMAP API

You need IMAP and SMTP settings and also provide some kind of an identification string value for this account. You can use the same IDs as your main system or generate some unique ones. This value is later needed to identify this account and to perform operations on it.

> **NB!** Trying to create a new account with the same ID updates the existing account.

```
$ curl -XPOST "localhost:3000/v1/account" -H "content-type: application/json" -d '{
    "account": "example",
    "name": "My Example Account",
    "imap": {
        "host": "imap.gmail.com",
        "port": 993,
        "secure": true,
        "auth": {
            "user": "myuser@gmail.com",
            "pass": "verysecret"
        }
    },
    "smtp": {
        "host": "smtp.gmail.com",
        "port": 465,
        "secure": true,
        "auth": {
            "user": "myuser@gmail.com",
            "pass": "verysecret"
        }
    }
}'
```

#### 3. That's about it to get started

Now whenever something happens you get a notification. If this is not enought then you can perform normal operations with the IMAP account as well.

See the entire API reference [here](https://imapapi.com/api.html).

#### List some messages

IMAP API returns paged results, newer messages first. So to get the first page or in other words the newest messages in a mailbox folder you can do it like this (notice the "example" id string that we set earlier in the request URL):

```
$ curl -XGET "localhost:3000/v1/account/example/messages?path=INBOX"
```

In the response you should see a listing of messages.

```json
{
    "page": 0,
    "pages": 10,
    "messages": [
        {
            "id": "AAAAAQAAAeE",
            "uid": 481,
            "date": "2019-10-07T06:05:23.000Z",
            "size": 4334,
            "subject": "Test message",
            "from": {
                "name": "Peter Põder",
                "address": "Peter.Poder@example.com"
            },
            "to": [
                {
                    "name": "",
                    "address": "andris@imapapi.com"
                }
            ],
            "messageId": "<0ebdd7b084794911b03986c827128f1b@example.com>",
            "text": {
                "id": "AAAAAQAAAeGTkaExkaEykA",
                "encodedSize": {
                    "plain": 17,
                    "html": 2135
                }
            }
        }
    ]
}
```

When fetching next page, add `page` query argument to the URL. Pages are zero indexes so if the server shows that there are 10 pages in total, it means you can query from `page=0` to `page=9`. If you want longer pages, use `pageSize` query argument.

```
$ curl -XGET "localhost:3000/v1/account/example/messages?path=INBOX&page=5"
```

#### Send an email

The following is an example of how to send a reply. In this case you should specify a reference message you are replying to (NB! this message must exist). Use the "id" from message listing as the "reference.message" value.

If referenced message was not found from the IMAP account then API responds with a 404 error and does not send out the reply.

```
curl -XPOST "localhost:3000/v1/account/example/submit" -H "content-type: application/json" -d '{
    "reference": {
        "message": "AAAAAQAAAeE",
        "action": "reply"
    },
    "from": {
        "name": "Example Sender",
        "address": "sender@example.com"
    },
    "to": [{
        "name": "Andris Reinman",
        "address": "andris@imapapi.com"
    }],
    "text": "my reply to you",
    "html": "<p>my reply to you</p>",
    "attachments": [
        {
            "filename": "checkmark.png",
            "content": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEUAAAD///+l2Z/dAAAAM0lEQVR4nGP4/5/h/1+G/58ZDrAz3D/McH8yw83NDDeNGe4Ug9C9zwz3gVLMDA/A6P9/AFGGFyjOXZtQAAAAAElFTkSuQmCC"
        }
    ]
}'
```

**NB!** if you are sending a standalone email then you most probably want to set `subject` value as well. For replies and forwards, IMAP API sets subject itself, based on the referenced message.

**When sending a referenced message:**

-   IMAP API sets correct In-Reply-To and Referenced message headers to the outgoing message
-   If subject is not set, then IMAP API derives it from the referenced message and adds Re: or Fwd: prefix to it
-   IMAP API sets `\Answered` flag to the referenced message

**For all messages:**

-   IMAP API uploads sent message to Sent Mail folder (if the folder can be detected automatically)
-   IMAP API does not upload to Sent Mail folder when the account is Gmail/GSuite as Gmail does this automatically
-   If account is created with `copy: false` option, then emails are not copied to Sent Mail folder

## Using OAuth2

Recommended approach for OAuth2 would be to manage access tokens outside of IMAP API by running an authentication server. In this case whenever IMAP API needs to authenticate an OAuth2 account, it makes a HTTP request to that authentication server. This server is responsible of respoding with a valid access token for IMAP API to use.

You can find an example authentication server implementation from [examples/auth-server.js](examples/auth-server.js).

Alternatively, for Gmail only, you can use IMAP API as the OAuth2 handler. In this case you would have to provide OAuth2 client id and client secret to IMAP API (see Oauth2 section in the Settings page) and then, when adding new accounts, use the Oauth2 option instead of manually specifying IMAP and SMTP settings.

In any case, your OAuth2 application for Gmail must support the following scope: `"https://mail.google.com/"`.

Gmail requires security auditing if you are using restricted Oauth2 scopes for public accounts but for internal accounts (eg. accounts in your own GSuite organization) and test accounts (up to 100 pre-defined accounts) you do not need any permissions.

#### To use authentication server:

-   You must set `useAuthServer:true` flag for the account settings and not set `auth` value
-   Set authentication server URL in the _Settings_ page, the same way you set the webhook URL
-   IMAP API makes HTTP request against authentication server URL with 2 extra GET params: `account` and `proto`, eg `url?account=example&proto=imap`
-   Authentication server must respond with a correct JSON structure for this account

**Register managed account**

```
curl -XPOST "localhost:3000/v1/account" -H "content-type: application/json" -d '{
    "account": "ouath-user",
    "name": "Example",
    "imap": {
        "host": "imap.gmail.com",
        "port": 993,
        "secure": true,
        "useAuthServer": true
    },
    "smtp": {
        "host": "smtp.gmail.com",
        "port": 465,
        "secure": true,
        "useAuthServer": true
    }
}'
```

**Auth server response for OAuth2 accounts:**

```json
{
    "user": "username@gmail.com",
    "accessToken": "jhdfgsjfmbsdmg"
}
```

**Auth server response for password based accounts:**

```json
{
    "user": "username@gmail.com",
    "pass": "verysecret"
}
```

## App access

By default IMAP API allows connections only from localhost. To change this either edit config file or use `--api.host="0.0.0.0"` cli option. This would enable outside access, so you should use firewall to only allow trusted sources.

## Deployment

### SystemD

See example [systemd unit file](systemd/imapapi.service) ro run IMAP API as a service and example [Nginx config file](systemd/nginx-proxy.conf) to serve IMAP API requests behind Nginx reverse proxy.

### Docker

#### Docker Hub

Pull IMAP API from Docker Hub

```
$ docker pull andris9/imapapi
```

Run the app and provide connection URL to Redis (this example assumes that Redis is running in host machine):

```
$ docker run -p 3000:3000 --env CMD_ARGS="\
  --dbs.redis=redis://host.docker.internal:6379/7 \
" \
andris9/imapapi
```

Next open http://127.0.0.1:3000 in your browser.

#### Docker compose

Clone this repo and in the root folder run the following to start both IMAP API and Redis containers.

```
$ docker-compose up
```

Next open http://127.0.0.1:3000 in your browser.

## Monitoring

There is a Prometheus output available at `/metrics` URL path of the app.

## Changelog

Changelog is available for Postal Systems subscribers [here](https://postalsys.com/changelog/package/imapapi).

## License

Licensed under GNU Affero General Public License v3.0 or later.

MIT-licensed version of IMAP API is available for [Postal Systems subscribers](https://postalsys.com/).
