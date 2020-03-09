# IMAP API

Self hosted application to access IMAP and SMTP accounts over REST.

## Use cases

-   Email applications (lightweight webmail and mobile apps etc. that do not want to process IMAP and MIME)
-   Syncing users' emails into your service and sending out emails on behalf of your users (helpdesk software etc.)

## Features

-   IMAP API allows simple access to IMAP accounts via REST based API. No need to know IMAP or MIME internals, you get a "normal" API with paged message listings. All text (that is subjects, email addresses, text and html content etc) is utf-8. Attachments are automatically decoded to binary representation.
-   Partial text download. You can obviously download the entire rfc822 formatted raw message but it might be easier to use provided paging and message details. This also allows to specifiy maximum size for downloaded text content. Sometimes automated cron scripts etc send emails with 10+MB text so to avoid downloading that stuff IMAP API allows to set max cap size for text.
-   Whenever something happens on tracked accounts IMAP API posts notification over a webhook. This includes new messages, deleted messages and message flag changes.
-   No data ever leaves your system
-   Easy email sending. If you specify the message you are responding to or forwarding then IMAP API sets all required headers, updates references message's flags in IMAP and also uploads message to the Sent Mail folder after sending.
-   IMAP API is a rather thin wrapper over IMAP. This means it does not have a storage of its own. It also means that if the IMAP connection is currently not open, you get a gateway error as a result of your API request.
-   IMAP API keeps a single persistent IMAP connection open against every registered user account. To stop syncing you must remove the account from IMAP API. This is different from some webmail implementations where connections are kept open during user session only.

## Comparison with other systems

#### 1. Context.io

It was closed down, so there's nothing to compare.

#### 2. Nylas Sync Engine (open source version)

Even though still available from Github, it has clearly been abandoned, so not going to look into it.

#### 3. Nylas Universal Email API

-   Nylas Email API is a service while IMAP API is a self hosted application. Your data never leaves your system when using IMAP API while Nylas can not even operate without copying your customers' data and emails to their servers.
-   Nylas in general tries to do everything while IMAP API only tries to handle the hard parts.
-   Nylas supports both IMAP and Exchange while IMAP API currently supports just IMAP. This might change in the future though.

## Usage

IMAP API requires Redis to be available. For any special configuration edit [config/default.toml](config/default.toml) configuration file.

```
$ npm install --production
$ npm start
```

Once application is started open http://127.0.0.1:3000/ for instructions and API documentation.

## Screenshots

**1. General overview**

![](https://cldup.com/UYvRSyD_ci.png)

**2. Documentation**

![](https://cldup.com/hmGEgSgOXX.png)

**3. Settings**

![](https://cldup.com/Ro-0lpKkuJ.png)

**4. Download stored logs**

![](https://cldup.com/0bQkl1mfIh.png)

**5. Swagger**

![](https://cldup.com/0Hg1VvhOGz.png)

## Example

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

## Using OAuth2

IMAP API does not manage OAuth2 access tokens, you have to provide these yourself. This means that every time IMAP API needs to authenticate an OAuth2 account, it makes a HTTP request to your authentication server. This server is responsible of respoding with a valid access token.

You can find an example authentication server implementation from [examples/auth-server.js](examples/auth-server.js).

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

## API

Entire API descripion is available in the application as a swagger page.

## Monitoring

There is a Prometheus output available at `/metrics` URL path of the app.

## Future features

-   **Horizontal scaling.** Currently you can start a single instance of IMAP API application. In the future you should be able to start several and in different servers, depending on the number of accounts you need to track.
-   **MS Exchange support.** Event though the app is called IMAP API the plan is to start supporting ActiveSync as well. It does not happen any time soon though, mostly because I do not have access to a good testing environment and I'm not competent enough to set up my own Exchange system.

## License

Licensed under GNU Affero General Public License v3.0 or later

Commercial license available at request. Contact andris@imapapi.com for license issues.
