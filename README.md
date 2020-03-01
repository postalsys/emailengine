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
$ npm install
$ npm start
```

Once application is started open http://127.0.0.1:3000/ for instructions and API documentation.

## Screenshots

![](https://cldup.com/2J7GkY2Hck.png)

![](https://cldup.com/FXLAIx7jv1.png)

![](https://cldup.com/xuM8QjP7-q.png)

![](https://cldup.com/dSa0mf3AjF.png)

## License

Licensed for evaluation use only
