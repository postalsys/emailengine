'use strict';

module.exports.rfc822 =
    '' +
    'Subject: test r n ' +
    'Content-type: multipart/mixed; boundary=abc\r\n' +
    '\r\n' +
    '--abc\r\n' +
    'Content-Type: text/plain\r\n' +
    '\r\n' +
    'Hello world!\r\n' +
    '--abc\r\n' +
    'Content-Type: image/png\r\n' +
    '\r\n' +
    'BinaryContent\r\n' +
    '--abc--\r\n';

module.exports.mimetree = {
    childNodes: [
        {
            header: ['Content-Type: text/plain'],
            parsedHeader: {
                'content-type': {
                    value: 'text/plain',
                    type: 'text',
                    subtype: 'plain',
                    params: {}
                }
            },
            body: 'Hello world!',
            multipart: false,
            boundary: false,
            lineCount: 1,
            size: 12
        },
        {
            header: ['Content-Type: image/png'],
            parsedHeader: {
                'content-type': {
                    value: 'image/png',
                    type: 'image',
                    subtype: 'png',
                    params: {}
                }
            },
            body: 'BinaryContent',
            multipart: false,
            boundary: false,
            lineCount: 1,
            size: 13
        }
    ],
    header: ['Subject: test', 'Content-type: multipart/mixed; boundary=abc'],
    parsedHeader: {
        'content-type': {
            value: 'multipart/mixed',
            type: 'multipart',
            subtype: 'mixed',
            params: {
                boundary: 'abc'
            },
            hasParams: true
        },
        subject: 'test'
    },
    body: '',
    multipart: 'mixed',
    boundary: 'abc',
    lineCount: 1,
    size: 0,
    text: '--abc\r\nHello world!\r\n--abc\r\nBinaryContent\r\n--abc--\r\n'
};

module.exports.bodystructure = [
    ['text', 'plain', null, null, null, '7bit', 12, 1, null, null, null, null],
    ['image', 'png', null, null, null, '7bit', 13, null, null, null, null],
    'mixed',
    ['boundary', 'abc'],
    null,
    null,
    null
];

module.exports.command =
    '* FETCH (BODYSTRUCTURE (("text" "plain" NIL NIL NIL "7bit" 12 1 NIL NIL NIL NIL) ("image" "png" NIL NIL NIL "7bit" 13 NIL NIL NIL NIL) "mixed" ("boundary" "abc") NIL NIL NIL))';
