/*eslint no-unused-expressions: 0, prefer-arrow-callback: 0 */

'use strict';

const chai = require('chai');
const imapHandler = require('../lib/handler/imap-handler');
const PassThrough = require('stream').PassThrough;
const crypto = require('crypto');
const expect = chai.expect;
chai.config.includeStack = true;

describe('IMAP Command Compile Stream', function() {
    describe('#compile', function() {
        it('should compile correctly', function(done) {
            let command =
                    '* FETCH (ENVELOPE ("Mon, 2 Sep 2013 05:30:13 -0700 (PDT)" NIL ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "tr.ee")) NIL NIL NIL "<-4730417346358914070@unknownmsgid>") BODYSTRUCTURE (("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 105 (NIL NIL ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "pangalink.net")) NIL NIL "<test1>" NIL) ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 12 0 NIL NIL NIL) 5 NIL NIL NIL)("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 83 (NIL NIL ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "pangalink.net")) NIL NIL "NIL" NIL) ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 12 0 NIL NIL NIL) 4 NIL NIL NIL)("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "QUOTED-PRINTABLE" 19 0 NIL NIL NIL) "MIXED" ("BOUNDARY" "----mailcomposer-?=_1-1328088797399") NIL NIL))',
                parsed = imapHandler.parser(command, {
                    allowUntagged: true
                });

            resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                expect(err).to.not.exist;
                expect(compiled.toString('binary')).to.equal(command);
                done();
            });
        });
    });

    describe('Types', function() {
        let parsed;

        beforeEach(function() {
            parsed = {
                tag: '*',
                command: 'CMD'
            };
        });

        describe('No attributes', function() {
            it('should compile correctly', function(done) {
                let command = '* CMD';

                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });
        });

        describe('TEXT', function() {
            it('should compile correctly', function(done) {
                parsed.attributes = [
                    {
                        type: 'TEXT',
                        value: 'Tere tere!'
                    }
                ];
                let command = '* CMD Tere tere!';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });
        });

        describe('SECTION', function() {
            it('should compile correctly', function(done) {
                parsed.attributes = [
                    {
                        type: 'SECTION',
                        section: [
                            {
                                type: 'ATOM',
                                value: 'ALERT'
                            }
                        ]
                    }
                ];
                let command = '* CMD [ALERT]';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });
        });

        describe('ATOM', function() {
            it('should compile correctly', function(done) {
                parsed.attributes = [
                    {
                        type: 'ATOM',
                        value: 'ALERT'
                    },
                    {
                        type: 'ATOM',
                        value: '\\ALERT'
                    },
                    {
                        type: 'ATOM',
                        value: 'NO ALERT'
                    }
                ];
                let command = '* CMD ALERT \\ALERT "NO ALERT"';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });
        });

        describe('SEQUENCE', function() {
            it('should compile correctly', function(done) {
                parsed.attributes = [
                    {
                        type: 'SEQUENCE',
                        value: '*:4,5,6'
                    }
                ];
                let command = '* CMD *:4,5,6';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });
        });

        describe('NIL', function() {
            it('should compile correctly', function(done) {
                parsed.attributes = [null, null];

                let command = '* CMD NIL NIL';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });
        });

        describe('TEXT', function() {
            it('should compile correctly', function(done) {
                parsed.attributes = [
                    // keep indentation
                    {
                        type: 'String',
                        value: 'Tere tere!',
                        sensitive: true
                    },
                    'Vana kere'
                ];

                let command = '* CMD "Tere tere!" "Vana kere"';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });

            it('should keep short strings', function(done) {
                parsed.attributes = [
                    // keep indentation
                    {
                        type: 'String',
                        value: 'Tere tere!'
                    },
                    'Vana kere'
                ];

                let command = '* CMD "Tere tere!" "Vana kere"';
                resolveStream(imapHandler.compileStream(parsed, true), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });

            it('should hide strings', function(done) {
                parsed.attributes = [
                    // keep indentation
                    {
                        type: 'String',
                        value: 'Tere tere!',
                        sensitive: true
                    },
                    'Vana kere'
                ];

                let command = '* CMD "(* value hidden *)" "Vana kere"';
                resolveStream(imapHandler.compileStream(parsed, true), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });

            it('should hide long strings', function(done) {
                parsed.attributes = [
                    // keep indentation
                    {
                        type: 'String',
                        value: 'Tere tere! Tere tere! Tere tere! Tere tere! Tere tere!'
                    },
                    'Vana kere'
                ];

                let command = '* CMD "(* 54B string *)" "Vana kere"';
                resolveStream(imapHandler.compileStream(parsed, true), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });
        });

        describe('No Command', function() {
            it('should compile correctly', function(done) {
                parsed = {
                    tag: '*',
                    attributes: [
                        1,
                        {
                            type: 'ATOM',
                            value: 'EXPUNGE'
                        }
                    ]
                };

                let command = '* 1 EXPUNGE';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });
        });
        describe('Literal', function() {
            it('shoud return as text', function(done) {
                let parsed = {
                    tag: '*',
                    command: 'CMD',
                    attributes: [
                        // keep indentation
                        {
                            type: 'LITERAL',
                            value: 'Tere tere!'
                        },
                        'Vana kere'
                    ]
                };

                let command = '* CMD {10}\r\nTere tere! "Vana kere"';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });

            it('should compile correctly without tag and command', function(done) {
                let parsed = {
                    attributes: [
                        {
                            type: 'LITERAL',
                            value: 'Tere tere!'
                        },
                        {
                            type: 'LITERAL',
                            value: 'Vana kere'
                        }
                    ]
                };
                let command = '{10}\r\nTere tere! {9}\r\nVana kere';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });

            it('shoud return byte length', function(done) {
                let parsed = {
                    tag: '*',
                    command: 'CMD',
                    attributes: [
                        // keep indentation
                        {
                            type: 'LITERAL',
                            value: 'Tere tere!'
                        },
                        'Vana kere'
                    ]
                };

                let command = '* CMD "(* 10B literal *)" "Vana kere"';
                resolveStream(imapHandler.compileStream(parsed, true), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });

            it('should mix with other values', function(done) {
                let s = new PassThrough();
                let str = 'abc'.repeat(100);
                let parsed = {
                    attributes: [
                        {
                            type: 'ATOM',
                            value: 'BODY'
                        },
                        {
                            type: 'LITERAL',
                            value: 'Tere tere!'
                        },
                        {
                            type: 'ATOM',
                            value: 'BODY'
                        },
                        {
                            type: 'LITERAL',
                            //value: str
                            value: s,
                            expectedLength: str.length
                        },
                        {
                            type: 'ATOM',
                            value: 'UID'
                        },
                        {
                            type: 'ATOM',
                            value: '12345'
                        }
                    ]
                };
                setImmediate(function() {
                    s.end(str);
                });
                let command = 'BODY {10}\r\nTere tere! BODY {' + str.length + '}\r\n' + str + ' UID 12345';
                resolveStream(imapHandler.compileStream(parsed), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });
            });

            it('shoud pipe literal streams', function(done) {
                let stream1 = new PassThrough();
                let stream2 = new PassThrough();
                let stream3 = new PassThrough();
                let parsed = {
                    tag: '*',
                    command: 'CMD',
                    attributes: [
                        // keep indentation
                        {
                            type: 'LITERAL',
                            value: 'Tere tere!'
                        },
                        {
                            type: 'LITERAL',
                            expectedLength: 5,
                            value: stream1
                        },
                        'Vana kere',
                        {
                            type: 'LITERAL',
                            expectedLength: 7,
                            value: stream2
                        },
                        {
                            type: 'LITERAL',
                            value: 'Kuidas laheb?'
                        },
                        {
                            type: 'LITERAL',
                            expectedLength: 5,
                            value: stream3
                        }
                    ]
                };

                let command = '* CMD {10}\r\nTere tere! {5}\r\ntest1 "Vana kere" {7}\r\ntest2   {13}\r\nKuidas laheb? {5}\r\ntest3';
                resolveStream(imapHandler.compileStream(parsed, false), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });

                setTimeout(() => {
                    stream2.end('test2');
                    setTimeout(() => {
                        stream1.end('test1');
                        setTimeout(() => {
                            stream3.end('test3');
                        }, 100);
                    }, 100);
                }, 100);
            });

            it('shoud pipe limited literal streams', function(done) {
                let stream1 = new PassThrough();
                let stream2 = new PassThrough();
                let stream3 = new PassThrough();
                let parsed = {
                    tag: '*',
                    command: 'CMD',
                    attributes: [
                        // keep indentation
                        {
                            type: 'LITERAL',
                            value: 'Tere tere!'
                        },
                        {
                            type: 'LITERAL',
                            expectedLength: 5,
                            value: stream1,
                            startFrom: 2,
                            maxLength: 2
                        },
                        'Vana kere',
                        {
                            type: 'LITERAL',
                            expectedLength: 7,
                            value: stream2,
                            startFrom: 2
                        },
                        {
                            type: 'LITERAL',
                            value: 'Kuidas laheb?'
                        },
                        {
                            type: 'LITERAL',
                            expectedLength: 7,
                            value: stream3,
                            startFrom: 2,
                            maxLength: 2
                        }
                    ]
                };

                let command = '* CMD {10}\r\nTere tere! {2}\r\nst "Vana kere" {5}\r\nst2   {13}\r\nKuidas laheb? {2}\r\nst';
                resolveStream(imapHandler.compileStream(parsed, false), (err, compiled) => {
                    expect(err).to.not.exist;
                    expect(compiled.toString('binary')).to.equal(command);
                    done();
                });

                setTimeout(() => {
                    stream2.end('test2');
                    setTimeout(() => {
                        stream1.end('test1');
                        setTimeout(() => {
                            stream3.end('test3');
                        }, 100);
                    }, 100);
                }, 100);
            });

            it('shoud pipe errors for literal streams', function(done) {
                let stream1 = new PassThrough();
                let parsed = {
                    tag: '*',
                    command: 'CMD',
                    attributes: [
                        // keep indentation
                        {
                            type: 'LITERAL',
                            value: 'Tere tere!'
                        },
                        {
                            type: 'LITERAL',
                            expectedLength: 5,
                            value: stream1
                        }
                    ]
                };

                resolveStream(imapHandler.compileStream(parsed, false), err => {
                    expect(err).to.exist;
                    done();
                });

                setTimeout(() => {
                    stream1.emit('error', new Error('Stream error'));
                }, 100);
            });
        });
    });

    describe('#LengthLimiter', function() {
        this.timeout(10000); //eslint-disable-line no-invalid-this

        it('should emit exact length', function(done) {
            let len = 1024;
            let limiter = new imapHandler.compileStream.LengthLimiter(len);
            let expected = 'X'.repeat(len);

            resolveStream(limiter, (err, value) => {
                value = value.toString();
                expect(err).to.not.exist;
                expect(value).to.equal(expected);
                done();
            });

            let emitted = 0;
            let emitter = () => {
                let str = 'X'.repeat(128);
                emitted += str.length;
                limiter.write(Buffer.from(str));
                if (emitted >= len) {
                    limiter.end();
                } else {
                    setTimeout(emitter, 100);
                }
            };

            setTimeout(emitter, 100);
        });

        it('should truncate output', function(done) {
            let len = 1024;
            let limiter = new imapHandler.compileStream.LengthLimiter(len - 100);
            let expected = 'X'.repeat(len - 100);

            resolveStream(limiter, (err, value) => {
                value = value.toString();
                expect(err).to.not.exist;
                expect(value).to.equal(expected);
                done();
            });

            let emitted = 0;
            let emitter = () => {
                let str = 'X'.repeat(128);
                emitted += str.length;
                limiter.write(Buffer.from(str));
                if (emitted >= len) {
                    limiter.end();
                } else {
                    setTimeout(emitter, 100);
                }
            };

            setTimeout(emitter, 100);
        });

        it('should skip output', function(done) {
            let len = 1024;
            let limiter = new imapHandler.compileStream.LengthLimiter(len - 100, false, 30);
            let expected = 'X'.repeat(len - 100 - 30);

            resolveStream(limiter, (err, value) => {
                value = value.toString();
                expect(err).to.not.exist;
                expect(value).to.equal(expected);
                done();
            });

            let emitted = 0;
            let emitter = () => {
                let str = 'X'.repeat(128);
                emitted += str.length;
                limiter.write(Buffer.from(str));
                if (emitted >= len) {
                    limiter.end();
                } else {
                    setTimeout(emitter, 100);
                }
            };

            setTimeout(emitter, 100);
        });

        it('should pad output', function(done) {
            let len = 1024;
            let limiter = new imapHandler.compileStream.LengthLimiter(len + 100);
            let expected = 'X'.repeat(len) + ' '.repeat(100);

            resolveStream(limiter, (err, value) => {
                value = value.toString();
                expect(err).to.not.exist;
                expect(value).to.equal(expected);
                done();
            });

            let emitted = 0;
            let emitter = () => {
                let str = 'X'.repeat(128);
                emitted += str.length;
                limiter.write(Buffer.from(str));
                if (emitted >= len) {
                    limiter.end();
                } else {
                    setTimeout(emitter, 100);
                }
            };

            setTimeout(emitter, 100);
        });

        it('should pipe to several streams', function(done) {
            let len = 1024;
            let start = 30;
            let margin = 200;
            let limiter = new imapHandler.compileStream.LengthLimiter(len - margin, false, start);
            let stream = new PassThrough();
            let input = crypto.randomBytes(len / 2).toString('hex');
            let expected1 = input.substr(start, len - margin - start);
            let expected2 = input.substr(len - margin);

            limiter.on('done', function(remainder) {
                stream.unpipe(limiter);
                if (remainder) {
                    stream.unshift(remainder);
                }
                limiter.end();
            });

            resolveStream(limiter, (err, value) => {
                value = value.toString();
                expect(err).to.not.exist;
                expect(value).to.equal(expected1);
                resolveStream(stream, (err, value) => {
                    value = value.toString();
                    expect(err).to.not.exist;
                    expect(value).to.equal(expected2);
                    done();
                });
            });

            let emitted = 0;
            let emitter = () => {
                let str = input.substr(emitted, 128);
                emitted += str.length;

                stream.write(Buffer.from(str));
                if (emitted >= len) {
                    stream.end();
                } else {
                    setImmediate(emitter);
                }
            };

            stream.pipe(limiter);
            setImmediate(emitter);
        });
    });
});

function resolveStream(stream, callback) {
    let chunks = [];
    let chunklen = 0;

    stream.on('readable', () => {
        let chunk;

        while ((chunk = stream.read()) !== null) {
            chunks.push(chunk);
            chunklen += chunk.length;
        }
    });

    stream.on('error', err => callback(err));
    stream.on('end', () => callback(null, Buffer.concat(chunks, chunklen)));
}
