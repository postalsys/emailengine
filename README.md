# IMAP API

Self hosted application to access IMAP accounts over REST.

-   IMAP API allows simple access to IMAP accounts via REST based API
-   Whenever something happens on tracked accounts IMAP API posts it to over a webhook
-   No data ever leaves your system

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
