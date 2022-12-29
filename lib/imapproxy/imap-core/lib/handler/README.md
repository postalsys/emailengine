# IMAP Handler

Server specific fork of [emailjs-imap-handler](https://github.com/emailjs/emailjs-imap-handler) for Node.js (v5+). Mostly differs from the upstream in the behavior for compiling – instead of compiling a command into long string, a Stream object is returned that can be piped directly to socket. Goal is to pass around large messages as streams instead of keeping these in memory.

This is more suitable for servers than clients as it is currently not possible to pause the output stream to wait for '+' tagged server response for literal values.

## Usage

```javascript
let handler = require('./lib/handler/imap-handler');
```

### Parse IMAP commands

To parse a command you need to have the command as one complete string (including all literals) without the ending &lt;CR&gt;&lt;LF&gt;

    imapHandler.parser(imapCommand);

Where

  * **imapCommand** is an IMAP string without the final line break

The function returns an object in the following form:

```javascript
{
    tag: "TAG",
    command: "COMMAND",
    attributes: [
        {type: "SEQUENCE", value: "sequence-set"},
        {type: "ATOM", value: "atom", section:[section_elements], partial: [start, end]},
        {type: "STRING", value: "string"},
        {type: "LITERAL", value: "literal"},
        [list_elements]
    ]
}
```

Where

  * **tag** is a string containing the tag
  * **command** is the first element after tag
  * **attributes** (if present) is an array of next elements

If section or partial values are not specified in the command, the values are also missing from the ATOM element

**NB!** Sequence numbers are identified as ATOM values if the value contains only numbers.
**NB!** NIL atoms are always identified as `null` values, even though in some cases it might be an ATOM with value `"NIL"`

For example

```javascript
let imapHandler = require("imap-handler-1");

imapHandler.parser("A1 FETCH *:4 (BODY[HEADER.FIELDS ({4}\r\nDate Subject)]<12.45> UID)");
```

Results in the following value:

```json
{
    "tag": "A1",
    "command": "FETCH",
    "attributes": [
        [
            {
                "type": "SEQUENCE",
                "value": "*:4"
            },
            {
                "type": "ATOM",
                "value": "BODY",
                "section": [
                    {
                        "type": "ATOM",
                        "value": "HEADER.FIELDS"
                    },
                    [
                        {
                            "type": "LITERAL",
                            "value": "Date"
                        },
                        {
                            "type": "ATOM",
                            "value": "Subject"
                        }
                    ]
                ],
                "partial": [
                    12,
                    45
                ]
            },
            {
                "type": "ATOM",
                "value": "UID"
            }
        ]
    ]
}
```

### Compile command objects into IMAP commands

You can "compile" parsed or self generated IMAP command objects to IMAP command strings with

    imapHandler.compileStream(commandObject, isLogging);

Where

  * **commandObject** is an object parsed with `imapHandler.parser()` or self generated
  * **isLogging** if set to true, do not include literals and long strings, useful when logging stuff and do not want to include message bodies etc. Additionally nodes with `sensitive: true` options are also not displayed (useful with logging passwords) if `logging` is used.

The function returns a Stream.

The input object differs from the parsed object with the following aspects:

  * **string**, **number** and **null** (null values are all non-number and non-string falsy values) are allowed to use directly - `{type: "STRING", value: "hello"}` can be replaced with `"hello"`
  * Additional types are used: `SECTION` which is an alias for `ATOM` and `TEXT` which returns the input string as given with no modification (useful for server messages).
  * **LITERAL** can takes streams as values. You do need to know the expected length beforehand though `{type:'LITERAL', expectedLength: 1024, value: stream}`. If the provided length does not match actual stream output length, then the output is either truncated or padded with space symbols to match the expected length.

```javascript
{
    type: 'LITERAL',
    value: stream,
    expectedLength: 100, // full stream length
    startFrom: 10, // optional start marker, do not emit bytes before it
    maxLength: 30 // optional length of the output stream
}
```

For example

```javascript
let command = {
    tag: "*",
    command: "OK",
    attributes: [
        {
            type: "SECTION",
            section: [
                {type: "ATOM", value: "ALERT"}
            ]
        },
        {type:"TEXT", value: "NB! The server is shutting down"}
    ]
};

imapHandler.compileStream(command).pipe(process.stdout);
// * OK [ALERT] NB! The server is shutting down
```
