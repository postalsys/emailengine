![twitter_header_photo_2](https://user-images.githubusercontent.com/132242/127487204-e27c980b-04b5-448c-b92f-e692fbefc1c5.png)

# EmailEngine Email API

Headless email client that makes IMAP and SMTP resources available over REST. Integrate email accounts with your service with ease!

> **EmailEngine** was previously known as **IMAP API**

## Use cases

-   Syncing users' emails to your service and sending out emails on behalf of your users
-   Integrating your app with a specific email account, eg. your support email
-   [Monitor INBOX and Junk folders](https://docs.emailengine.app/measuging-inbox-spam-placement/) of a test email account to see where the emails you send out end up in
-   Lightweight webmail and mobile email apps that do not want to process IMAP and MIME

## Quickstart

1. Install Node.js and Redis
2. Install and run EmailEngine:

```
$ npm install -g emailengine-app
$ emailengine
```

3. Open [http://127.0.0.1:3000/](http://127.0.0.1:3000/) in your browser

> **Tip** For human readable logs you can use _pino-pretty_ (`npm install -g pino-pretty`) by piping EmailEngine output to it: `emailengine | pino-pretty`

## Demo

[![Using EmailEngine](https://img.youtube.com/vi/shHZHowVnYw/0.jpg)](https://www.youtube.com/watch?v=shHZHowVnYw)

This video shows how to

1. Install and start EmailEngine
2. Configure webhooks destination using the web UI (webhook handling from https://webhook.site/)
3. Create a new email account at https://ethereal.email/
4. Open Swagger documentation page that also serves as an API playground
5. Using the API playground to add a new IMAP/SMTP account using the id "example"
6. Check the webhook listing to see the notification about found messages from the added account (includes limited information)
7. Using the ID from the webhook fetch all data for the message (decoded addresses, subject, text etc, also original headers as an array)

## Features

-   EmailEngine allows simple access to IMAP accounts via REST based API. No need to know IMAP or MIME internals, you get a "normal" API with paged message listings.
-   All text (that is subjects, email addresses, text and html content etc) is utf-8. Attachments are automatically decoded to binary representation.
-   Whenever something happens on tracked accounts EmailEngine posts notification over a webhook. This includes new messages, deleted messages and message flag changes.
-   Easy email sending. If you specify the message you are responding to or forwarding then EmailEngine sets all required headers, updates references message's flags in IMAP and also uploads message to the Sent Mail folder after sending.
-   No data ever leaves your system (read about data and security compliance [here](https://docs.emailengine.app/data-compliance/))
-   If you are running into IP based rate limiting then EmailEngine can make use of multiple local network interfaces to make connections from different IP addresses.

## Requirements

-   **Redis** – any version
-   **Node.js** - v12.16.0 or newer

> **NB!** Try to keep the latency between EmailEngine and Redis as low as possible, best if these would run in the same machine or at least in the same DC. EmailEngine runs a separate Redis command for each message in a folder when syncing messages, so if the latency is not low then it takes a long time to sync a folder with a lot of messages,

## Documentation

-   [API Reference](https://api.emailengine.app/)
-   [Blog posts](https://docs.emailengine.app/tag/email-engine/)
-   For Postman you can import OpenAPI specification [here](https://api.emailengine.app/swagger.json).

## Config mapping

#### General settings

| Configuration option | CLI argument                         | ENV value                     | Default                      |
| -------------------- | ------------------------------------ | ----------------------------- | ---------------------------- |
| IMAP Worker count    | `--workers.imap=4`                   | `EENGINE_WORKERS=4`           | `4`                          |
| Redis connection URL | `--dbs.redis="url"`                  | `EENGINE_REDIS="url"`         | `"redis://127.0.0.1:6379/8"` |
| Prepared settings    | `--settings='{"JSON"}'`              | `EENGINE_SETTINGS='{"JSON"}'` | not set                      |
| Encryption secret    | `--service.secret="****"`            | `EENGINE_SECRET="****"`       | not set                      |
| Local addresses      | `--service.localAddresses="ip1,ip2"` | `EENGINE_ADDRESSES="ip1,ip2"` | default interface            |
| Max command duration | `--service.commandTimeout=10s`       | `EENGINE_TIMEOUT=10s`         | `10s`                        |
| Log level            | `--log.level="level"`                | `EENGINE_LOG_LEVEL=level`     | `"trace"`                    |

#### API server settings

| Configuration option | CLI argument             | ENV value                  | Default       |
| -------------------- | ------------------------ | -------------------------- | ------------- |
| Host to bind to      | `--api.host="1.2.3.4"`   | `EENGINE_HOST="1.2.3.4"`   | `"127.0.0.1"` |
| Port to bind to      | `--api.port=port`        | `EENGINE_PORT=port`        | `3000`        |
| Max attachment size  | `--api.maxSize=5M`       | `EENGINE_MAX_SIZE=5M`      | `5M`          |
| API Basic Auth       | `--api.auth="user:pass"` | `EENGINE_AUTH="user:pass"` | not set       |

#### SMTP server settings

> SMTP server is **only enabled if SMTP password is set**.

When authenticating via SMTP use the account Id as the username and SMTP password as the password to send emails using the selected account.

| Configuration option | CLI argument            | ENV value                     | Default       |
| -------------------- | ----------------------- | ----------------------------- | ------------- |
| SMTP password        | `--smtp.secret=pass`    | `EENGINE_SMTP_SECRET=pass`    | not set       |
| Host to bind to      | `--smtp.host="1.2.3.4"` | `EENGINE_SMTP_HOST="1.2.3.4"` | `"127.0.0.1"` |
| Port to bind to      | `--smtp.port=port`      | `EENGINE_SMTP_PORT=port`      | `2525`        |
| Behind HAProxy       | `--smtp.proxy=true`     | `EENGINE_SMTP_PROXY=true`     | `false`       |

When sending emails via SMTP you can use the following headers

-   **X-EE-Send-At: timestamp** to schedule sending to a future time. This matches `sendAt` property of the [POST /submit](https://api.emailengine.app/#operation/postV1AccountAccountSubmit) API endpoint.

---

> **NB!** environment variables override CLI arguments. CLI arguments override configuration file values.

If available then EmailEngine uses dotenv file from current working directory to populate environment variables.

#### Redis connection

```
$ emailengine --dbs.redis="redis://127.0.0.1:6379/8"
```

#### Prepared settings

If you do not want to update application settings via API calls then you can provide the initial settings via a command line option (`--settings`) or environment variable (`EENGINE_SETTINGS`). The value must be a valid JSON string that could be used against the `/settings` API endpoint. The behavior is identical to calling the same thing via API, so whatever settings are given are stored in the DB.

```
$ emailengine --settings='{"webhooks": "https://webhook.site/14e88aea-3391-48b2-a4e6-7b617280155d","webhookEvents":["messageNew"]}'
```

When using Docker Compose where environment variables are defined in YAML format, you can use the following environment variable for prepared settings:

```yaml
EENGINE_SETTINGS: >
    {
        "webhooks": "https://webhook.site/f6a00604-7407-4f40-9a8e-ab68a31a3503",
        "webhookEvents": [
            "messageNew", "messageDeleted"
        ]
    }
```

If settings object fails validation then the application does not start.

#### Encryption secret

By default account passwords are stored as cleartext in Redis. You can set an encryption secret that will be used to encrypt these passwords.

See the documentation for encryption [here](https://docs.emailengine.app/enabling-secret-encryption/).

> EmailEngine is also able to use [Vault](https://www.vaultproject.io/) to store the encryption secret. See Vault usage docs [here](https://docs.emailengine.app/enabling-secret-encryption/#using-vault)

#### Local addresses

If your server has multiple IP addresses/interfaces available then you can provide a comma separated list of these IP addresses for EmailEngine to bound to when making outbound connections.

This is mostly useful if you are making a large amount of connections and might get rate limited by destination server based on your IP address. Using multiple local addresses allows to distribute separate connections between separate IP addresses. An address is selected randomly from the list whenever making a new IMAP connection.

```
$ emailengine --service.localAddresses="192.168.1.176,192.168.1.177,192.168.1.178"
```

If those interfaces aren't actually available then TCP connections will fail, so check the logs.

**Local addresses and SMTP**

By default when EmailEngine is sending an email to SMTP it uses local hostname in the SMTP greeting. This hostname is resolved by `os.hostname()`. Sometimes hostname is using invalid format (eg. `Servername_local` as undersore is not actually allowed) and depending on the SMTP server it might reject such connection.

To overcome you can set the local hostname to use by appending the hostname to the IP address, separated by pipe symbol

```
$ emailengine --service.localAddresses="ip1|hostname1,ip2|hostname2,ip3|hostname3"
```

For example when using AWS you can use the private interface IP but set a public hostname.

```
$ emailengine --service.localAddresses="172.31.1.2|ec2-18-194-1-2.eu-central-1.compute.amazonaws.com"
```

So in general the hostname shoud be whatever the public interface IP (this is what the SMTP server sees) resolves to.

#### Authentication

EmailEngine supports Basic Auth with a single user. This is a convenience option only, for any kind of production use you should implement your own user management and limit access with a firewall to trusted machines only.

```
$ emailengine --api.auth="user:password"
```

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

## Webhooks

EmailEngine sends webhooks to a predefined URL whenever something happens on an account.

Easiest way to set it up would be to use the built in [web interface](http://127.0.0.1:3000). Open the <em>Settings</em> tab and set an URL for webhooks. You can also select specific events to listen for.

For example if flags are updated for a message you'd get a POST notification that looks like this:

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

## API usage examples

> See the entire API Reference [here](https://api.emailengine.app/)

### Register an email account with EmailEngine

When registering a new account you have to provide an unique account ID for it. This could be any text identifer, even an email address.

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

> This example uses a Gmail account but in reality it might be difficult to get past Gmail's security restrictions. In this case use [OAuth2](https://docs.emailengine.app/setting-up-gmail-oauth2-for-imap-api/) instead of password authentication.

### List some messages

EmailEngine returns paged results, newer messages first. So to get the first page or in other words the newest messages in a mailbox folder you can do it like this (notice the "example" id string that we set earlier in the request URL):

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
                    "address": "andris@emailengine.app"
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

### Send an email

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
        "address": "andris@emailengine.app"
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

**NB!** if you are sending a standalone email then you most probably want to set `subject` value as well. For replies and forwards, EmailEngine sets subject itself, based on the referenced message.

**When sending a referenced message:**

-   EmailEngine sets correct In-Reply-To and Referenced message headers to the outgoing message
-   If subject is not set, then EmailEngine derives it from the referenced message and adds Re: or Fwd: prefix to it
-   EmailEngine sets `\Answered` flag to the referenced message

**For all messages:**

-   EmailEngine uploads sent message to Sent Mail folder (if the folder can be detected automatically)
-   EmailEngine does not upload to Sent Mail folder when the account is Gmail/GSuite as Gmail does this automatically
-   If account is created with `copy: false` option, then emails are not copied to Sent Mail folder

## Using OAuth2

Recommended approach for OAuth2 would be to manage access tokens outside of EmailEngine by running an authentication server. In this case whenever EmailEngine needs to authenticate an OAuth2 account, it makes a HTTP request to that authentication server. This server is responsible of respoding with a valid access token for EmailEngine to use.

You can find an example authentication server implementation from [examples/auth-server.js](examples/auth-server.js).

Alternatively, for Gmail only, you can use EmailEngine as the OAuth2 handler. In this case you would have to provide OAuth2 client id and client secret to EmailEngine (see OAuth2 section in the Settings page) and then, when adding new accounts, use the OAuth2 option instead of manually specifying IMAP and SMTP settings.

In any case, your OAuth2 application for Gmail must support the following scope: `"https://mail.google.com/"`.

Gmail requires security auditing if you are using restricted OAuth2 scopes for public accounts but for internal accounts (eg. accounts in your own GSuite organization) and test accounts (up to 100 pre-defined accounts) you do not need any permissions.

Instructions for setting up OAuth2 with EmailEngine can be found [here](https://docs.emailengine.app/setting-up-gmail-oauth2-for-imap-api/).

#### To use authentication server:

-   You must set `useAuthServer:true` flag for the account settings and not set `auth` value
-   Set authentication server URL in the _Settings_ page, the same way you set the webhook URL
-   EmailEngine makes HTTP request against authentication server URL with 2 extra GET params: `account` and `proto`, eg `url?account=example&proto=imap`
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

By default EmailEngine allows connections only from localhost. To change this either edit config file or use `--api.host="0.0.0.0"` cli option. This would enable outside access, so you should use firewall to only allow trusted sources.

## Deployment

### SystemD

See example [systemd unit file](systemd/emailengine.service) ro run EmailEngine as a service and example [Nginx config file](systemd/nginx-proxy.conf) to serve EmailEngine requests behind Nginx reverse proxy.

### Docker

#### Docker Hub

Pull EmailEngine from Docker Hub

```
$ docker pull andris9/emailengine
```

Run the app and provide connection URL to Redis (this example assumes that Redis is running in host machine):

```
$ docker run -p 3000:3000 --env CMD_ARGS="\
  --dbs.redis=redis://host.docker.internal:6379/7 \
" \
andris9/emailengine
```

Next open http://127.0.0.1:3000 in your browser.

#### Docker compose

Clone this repo and in the root folder run the following to start both EmailEngine and Redis containers.

```
$ docker-compose up
```

Next open http://127.0.0.1:3000 in your browser.

## Monitoring

There is a Prometheus output available at `/metrics` URL path of the app.

## Security and Data compliance

[Read here](https://docs.emailengine.app/data-compliance/).

## Changelog

Changelog is available for Postal Systems subscribers [here](https://postalsys.com/changelog/package/emailengine-app).

## Licensing

Licensed under GNU Affero General Public License v3.0 or later.

MIT-licensed version of EmailEngine is available for [Postal Systems subscribers](https://postalsys.com/).
