# API

```
curl -XPOST "localhost:3000/v1/account" -H "content-type: application/json" -d '{
    "account": "example",
    "name": "Example",
    "imap": {
        "host": "localhost",
        "port": 9993,
        "secure": true,
        "auth": {
            "user": "myuser2",
            "pass": "verysecret"
        },
        "tls": {
            "rejectUnauthorized": false
        }
    },
    "smtp": {
        "host": "localhost",
        "port": 1025,
        "secure": false,
        "auth": {
            "user": "myuser2",
            "pass": "verysecret"
        },
        "tls": {
            "rejectUnauthorized": false
        }
    }
}'
```

```
curl -XPUT "localhost:3000/account/example" -H "content-type: application/json" -d '{
    "imap": {
        "host": "localhost",
        "port": 9993,
        "secure": true,
        "auth": {
            "user": "myuser2",
            "pass": "verysecret"
        },
        "tls": {
            "rejectUnauthorized": false
        }
    }
}'
```

```
curl -XPOST "localhost:3000/v1/verifyAccount" -H "content-type: application/json" -d '{
    "imap": {
        "host": "localhost",
        "port": 9993,
        "secure": true,
        "auth": {
            "user": "myuser2",
            "pass": "verysecret"
        },
        "tls": {
            "rejectUnauthorized": false
        }
    },
    "smtp": {
        "host": "localhost",
        "port": 1025,
        "secure": false,
        "auth": {
            "user": "myuser2",
            "pass": "verysecret"
        },
        "tls": {
            "rejectUnauthorized": false
        }
    }
}'
```

```
curl -XPOST "localhost:3000/v1/account/pangalink/submit" -H "content-type: application/json" -d '{
    "reference": {
        "message": "AAAAAQAACnA",
        "action": "reply"
    },
    "from": {
        "name": "Pangalink",
        "address": "no-reply@pangalink.net"
    },
    "to": [{
        "name": "Andris Reinman",
        "address": "andris@emailengine.app"
    }],
    "subject": "test kiri",
    "text": "eriti test kiri",
    "html": "<p>eriti test kiri</p>",
    "attachments": [
        {
            "filename": "checkmark.png",
            "content": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAABlBMVEUAAAD///+l2Z/dAAAAM0lEQVR4nGP4/5/h/1+G/58ZDrAz3D/McH8yw83NDDeNGe4Ug9C9zwz3gVLMDA/A6P9/AFGGFyjOXZtQAAAAAElFTkSuQmCC"
        }
    ]
}'
```

```
curl -XDELETE "localhost:3000/v1/account/example"
```

```
curl -XGET "localhost:3000/v1/account/example/mailboxes"
```

```
curl -XGET "localhost:3000/v1/account/example/messages?path=INBOX&page=1"
```

```
curl -XGET "localhost:3000/v1/account/pangalink/message/AAAAAQAAMlw"
```

```
curl -XGET "localhost:3000/v1/account/pangalink/message/AAAAAQAAMlw/source"
```

```
curl -XGET "localhost:3000/v1/account/example/text/AAAAAQAAAeGTkaExkaEykA?textType=html&maxBytes=200"
```

```
curl -XPUT "localhost:3000/v1/account/pangalink/message/AAAAAQAAMlw" -H "content-type: application/json" -d '{
    "flags": {
        "add": ["test2", "test3"],
        "delete": ["test1"]
    }
}'
```
