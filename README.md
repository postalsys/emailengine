# IMAP API

Self hosted application to access IMAP accounts over REST.

## Features

-   IMAP API allows simple access to IMAP accounts via REST based API. No need to know IMAP or MIME internals, you get a "normal" API with paged message listings. All text (that is subjects, email addresses, text and html content etc) is utf-8. Attachments are automatically decoded to binary representation.
-   Partial text download. You can obviously download the entire rfc822 formatted raw message but it might be easier to use provided paging and message details. This also allows to specifiy maximum size for downloaded text content. Sometimes automated cron scripts etc send emails with 10+MB text so to avoid downloading that stuff IMAP API allows to set max cap size for text.
-   Whenever something happens on tracked accounts IMAP API posts notification over a webhook. This includes new messages, deleted messages and message flag changes.
-   No data ever leaves your system
-   Easy email sending. If you specify the message you are responding to or forwarding then IMAP API sets all required headers, updates references message's flags in IMAP and also uploads message to the Sent Mail folder after sending.
-   IMAP API is a rather thin wrapper over IMAP. This means it does not have a storage of its own. It also means that if the IMAP connection is currently not open, you get a gateway error as a result of your API request.

## Usage

IMAP API requires Redis to be available. For any special configuration edit [config/default.toml](config/default.toml) configuration file.

```
$ npm install --production
$ npm start
```

Once application is started open http://127.0.0.1:3000/ for instructions and API documentation.

## Screenshots

![](https://cldup.com/2J7GkY2Hck.png)

![](https://cldup.com/FXLAIx7jv1.png)

![](https://cldup.com/xuM8QjP7-q.png)

![](https://cldup.com/dSa0mf3AjF.png)

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

#### Send an email

The following is an example of how to send a reply. In this case you should specify a reference message you are replying to (NB! this message must exist). Use the "id" from message listing as the "reference.message" value.

If referenced message was not found from the IMAP account then API responds with a 404 error and does not send out the reply.

```
curl -XPOST "localhost:3000/v1/account/pangalink/submit" -H "content-type: application/json" -d '{
    "reference": {
        "message": "AAAAAQAAAeE",
        "action": "reply"
    },
    "from": {
        "name": "Pangalink",
        "address": "no-reply@pangalink.net"
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

When sending a referenced message:

-   IMAP API sets correct In-Reply-To and Referenced message headers to the outgoing message
-   If subject is not set, then IMAP API derives it from the referenced message and adds Re: or Fwd: prefix to it
-   IMAP API sets `\Answered` flag to the referenced message

For all messages:

-   IMAP API uploads sent message to Sent Mail folder (if the folder can be detected automatically)
-   IMAP API does not upload to Sent Mail folder when the account is Gmail/GSuite as Gmail does this automatically

#### API

Entire API descripion is available in the application as a swagger page.

## License

Licensed for evaluation use only
