/*eslint no-unused-expressions: 0, prefer-arrow-callback: 0 */

'use strict';

const chai = require('chai');
const imapHandler = require('../lib/handler/imap-handler');
const mimetorture = require('./fixtures/mimetorture');

const expect = chai.expect;
chai.config.includeStack = true;

describe('IMAP Command Parser', function() {
    describe('get tag', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD').tag).to.equal('TAG1');
        });

        it('should fail for unexpected WS', function() {
            expect(function() {
                imapHandler.parser(' TAG CMD');
            }).to.throw(Error);
        });

        it('should * OK ', function() {
            expect(function() {
                imapHandler.parser(' TAG CMD');
            }).to.throw(Error);
        });

        it('should + OK ', function() {
            expect(imapHandler.parser('+ TAG CMD').tag).to.equal('+');
        });

        it('should allow untagged', function() {
            expect(function() {
                imapHandler.parser('* CMD');
            }).to.not.throw(Error);
        });

        it('should fail for empty tag', function() {
            expect(function() {
                imapHandler.parser('');
            }).to.throw(Error);
        });

        it('should fail for unexpected end', function() {
            expect(function() {
                imapHandler.parser('TAG1');
            }).to.throw(Error);
        });

        it('should fail for invalid char', function() {
            expect(function() {
                imapHandler.parser('TAG"1 CMD');
            }).to.throw(Error);
        });
    });

    describe('get arguments', function() {
        it('should allow trailing whitespace and empty arguments', function() {
            expect(function() {
                imapHandler.parser('* SEARCH ');
            }).to.not.throw(Error);
        });
    });

    describe('get command', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD').command).to.equal('CMD');
        });

        it('should work for multi word command', function() {
            expect(imapHandler.parser('TAG1 UID FETCH').command).to.equal('UID FETCH');
        });

        it('should fail for unexpected WS', function() {
            expect(function() {
                imapHandler.parser('TAG1  CMD');
            }).to.throw(Error);
        });

        it('should fail for empty command', function() {
            expect(function() {
                imapHandler.parser('TAG1 ');
            }).to.throw(Error);
        });

        it('should fail for invalid char', function() {
            expect(function() {
                imapHandler.parser('TAG1 CM=D');
            }).to.throw(Error);
        });
    });

    describe('get attribute', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD FED').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'FED'
                }
            ]);
        });

        it('should succeed for single whitespace between values', function() {
            expect(imapHandler.parser('TAG1 CMD FED TED').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'FED'
                },
                {
                    type: 'ATOM',
                    value: 'TED'
                }
            ]);
        });

        it('should succeed for ATOM', function() {
            expect(imapHandler.parser('TAG1 CMD ABCDE').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'ABCDE'
                }
            ]);

            expect(imapHandler.parser('TAG1 CMD ABCDE DEFGH').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'ABCDE'
                },
                {
                    type: 'ATOM',
                    value: 'DEFGH'
                }
            ]);

            expect(imapHandler.parser('TAG1 CMD %').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: '%'
                }
            ]);

            expect(imapHandler.parser('TAG1 CMD \\*').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: '\\*'
                }
            ]);

            expect(imapHandler.parser('12.82 STATUS [Gmail].Trash (UIDNEXT UNSEEN HIGHESTMODSEQ)').attributes).to.deep.equal([
                // keep indentation
                {
                    type: 'ATOM',
                    value: '[Gmail].Trash'
                },
                [
                    {
                        type: 'ATOM',
                        value: 'UIDNEXT'
                    },
                    {
                        type: 'ATOM',
                        value: 'UNSEEN'
                    },
                    {
                        type: 'ATOM',
                        value: 'HIGHESTMODSEQ'
                    }
                ]
            ]);
        });

        it('should not succeed for ATOM', function() {
            expect(function() {
                imapHandler.parser('TAG1 CMD \\*a');
            }).to.throw(Error);
        });
    });

    describe('get string', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD "ABCDE"').attributes).to.deep.equal([
                {
                    type: 'STRING',
                    value: 'ABCDE'
                }
            ]);

            expect(imapHandler.parser('TAG1 CMD "ABCDE" "DEFGH"').attributes).to.deep.equal([
                {
                    type: 'STRING',
                    value: 'ABCDE'
                },
                {
                    type: 'STRING',
                    value: 'DEFGH'
                }
            ]);
        });

        it('should not explode on invalid char', function() {
            expect(imapHandler.parser('* 1 FETCH (BODY[] "\xc2")').attributes).to.deep.equal([
                // keep indentation
                {
                    type: 'ATOM',
                    value: 'FETCH'
                },
                [
                    {
                        type: 'ATOM',
                        value: 'BODY',
                        section: []
                    },
                    {
                        type: 'STRING',
                        value: '\xc2'
                    }
                ]
            ]);
        });
    });

    describe('get list', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD (1234)').attributes).to.deep.equal([
                [
                    {
                        type: 'ATOM',
                        value: '1234'
                    }
                ]
            ]);
            expect(imapHandler.parser('TAG1 CMD (1234 TERE)').attributes).to.deep.equal([
                [
                    {
                        type: 'ATOM',
                        value: '1234'
                    },
                    {
                        type: 'ATOM',
                        value: 'TERE'
                    }
                ]
            ]);
            expect(imapHandler.parser('TAG1 CMD (1234)(TERE)').attributes).to.deep.equal([
                [
                    {
                        type: 'ATOM',
                        value: '1234'
                    }
                ],
                [
                    {
                        type: 'ATOM',
                        value: 'TERE'
                    }
                ]
            ]);
            expect(imapHandler.parser('TAG1 CMD ( 1234)').attributes).to.deep.equal([
                [
                    {
                        type: 'ATOM',
                        value: '1234'
                    }
                ]
            ]);
            // Trailing whitespace in a BODYSTRUCTURE atom list has been
            // observed on yahoo.co.jp's
            expect(imapHandler.parser('TAG1 CMD (1234 )').attributes).to.deep.equal([
                [
                    {
                        type: 'ATOM',
                        value: '1234'
                    }
                ]
            ]);
            expect(imapHandler.parser('TAG1 CMD (1234) ').attributes).to.deep.equal([
                [
                    {
                        type: 'ATOM',
                        value: '1234'
                    }
                ]
            ]);
        });
    });

    describe('nested list', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD (((TERE)) VANA)').attributes).to.deep.equal([
                [
                    [
                        [
                            {
                                type: 'ATOM',
                                value: 'TERE'
                            }
                        ]
                    ],
                    {
                        type: 'ATOM',
                        value: 'VANA'
                    }
                ]
            ]);
            expect(imapHandler.parser('TAG1 CMD (( (TERE)) VANA)').attributes).to.deep.equal([
                [
                    [
                        [
                            {
                                type: 'ATOM',
                                value: 'TERE'
                            }
                        ]
                    ],
                    {
                        type: 'ATOM',
                        value: 'VANA'
                    }
                ]
            ]);
            expect(imapHandler.parser('TAG1 CMD (((TERE) ) VANA)').attributes).to.deep.equal([
                [
                    [
                        [
                            {
                                type: 'ATOM',
                                value: 'TERE'
                            }
                        ]
                    ],
                    {
                        type: 'ATOM',
                        value: 'VANA'
                    }
                ]
            ]);
        });
    });

    describe('get literal', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD {4}\r\n', { literals: [Buffer.from('abcd')] }).attributes).to.deep.equal([
                {
                    type: 'LITERAL',
                    value: 'abcd'
                }
            ]);

            expect(imapHandler.parser('TAG1 CMD {4}\r\n {4}\r\n', { literals: [Buffer.from('abcd'), Buffer.from('kere')] }).attributes).to.deep.equal([
                {
                    type: 'LITERAL',
                    value: 'abcd'
                },
                {
                    type: 'LITERAL',
                    value: 'kere'
                }
            ]);

            expect(imapHandler.parser('TAG1 CMD ({4}\r\n {4}\r\n)', { literals: [Buffer.from('abcd'), Buffer.from('kere')] }).attributes).to.deep.equal([
                [
                    {
                        type: 'LITERAL',
                        value: 'abcd'
                    },
                    {
                        type: 'LITERAL',
                        value: 'kere'
                    }
                ]
            ]);
        });

        it('should fail', function() {
            expect(function() {
                imapHandler.parser('TAG1 CMD {4}\r\n{4}  \r\n', { literals: [Buffer.from('abcd'), Buffer.from('kere')] });
            }).to.throw(Error);
        });

        it('should allow zero length literal in the end of a list', function() {
            expect(imapHandler.parser('TAG1 CMD ({0}\r\n)').attributes).to.deep.equal([
                [
                    {
                        type: 'LITERAL',
                        value: ''
                    }
                ]
            ]);
        });
    });

    describe('ATOM Section', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD BODY[]').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'BODY',
                    section: []
                }
            ]);
            expect(imapHandler.parser('TAG1 CMD BODY[(KERE)]').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'BODY',
                    section: [
                        [
                            {
                                type: 'ATOM',
                                value: 'KERE'
                            }
                        ]
                    ]
                }
            ]);
        });
        it('will not fail due to trailing whitespace', function() {
            // We intentionally have trailing whitespace in the section here
            // because we altered the parser to handle this when we made it
            // legal for lists and it makes sense to accordingly test it.
            // However, we have no recorded incidences of this happening in
            // reality (unlike for lists).
            expect(imapHandler.parser('TAG1 CMD BODY[HEADER.FIELDS (Subject From) ]').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'BODY',
                    section: [
                        // keep indentation
                        {
                            type: 'ATOM',
                            value: 'HEADER.FIELDS'
                        },
                        [
                            {
                                type: 'ATOM',
                                value: 'Subject'
                            },
                            {
                                type: 'ATOM',
                                value: 'From'
                            }
                        ]
                    ]
                }
            ]);
        });
        it('should fail where default BODY and BODY.PEEK are allowed to have sections', function() {});
        expect(function() {
            imapHandler.parser('TAG1 CMD KODY[]');
        }).to.throw(Error);
    });

    describe('Human readable', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('* OK [CAPABILITY IDLE] Hello world!')).to.deep.equal({
                command: 'OK',
                tag: '*',
                attributes: [
                    {
                        section: [
                            {
                                type: 'ATOM',
                                value: 'CAPABILITY'
                            },
                            {
                                type: 'ATOM',
                                value: 'IDLE'
                            }
                        ],
                        type: 'ATOM',
                        value: ''
                    },
                    {
                        type: 'TEXT',
                        value: 'Hello world!'
                    }
                ]
            });

            expect(imapHandler.parser('* OK Hello world!')).to.deep.equal({
                command: 'OK',
                tag: '*',
                attributes: [
                    {
                        type: 'TEXT',
                        value: 'Hello world!'
                    }
                ]
            });

            expect(imapHandler.parser('* OK')).to.deep.equal({
                command: 'OK',
                tag: '*'
            });

            // USEATTR is from RFC6154; we are testing that just an ATOM
            // on its own will parse successfully here.  (All of the
            // RFC5530 codes are also single atoms.)
            expect(imapHandler.parser('TAG1 OK [USEATTR] \\All not supported')).to.deep.equal({
                tag: 'TAG1',
                command: 'OK',
                attributes: [
                    {
                        type: 'ATOM',
                        value: '',
                        section: [
                            {
                                type: 'ATOM',
                                value: 'USEATTR'
                            }
                        ]
                    },
                    {
                        type: 'TEXT',
                        value: '\\All not supported'
                    }
                ]
            });

            // RFC5267 defines the NOUPDATE error.  Including for quote /
            // string coverage.
            expect(imapHandler.parser('* NO [NOUPDATE "B02"] Too many contexts')).to.deep.equal({
                tag: '*',
                command: 'NO',
                attributes: [
                    {
                        type: 'ATOM',
                        value: '',
                        section: [
                            {
                                type: 'ATOM',
                                value: 'NOUPDATE'
                            },
                            {
                                type: 'STRING',
                                value: 'B02'
                            }
                        ]
                    },
                    {
                        type: 'TEXT',
                        value: 'Too many contexts'
                    }
                ]
            });

            // RFC5464 defines the METADATA response code; adding this to
            // ensure the transition for when '2199' hits ']' is handled
            // safely.
            expect(imapHandler.parser('TAG1 OK [METADATA LONGENTRIES 2199] GETMETADATA complete')).to.deep.equal({
                tag: 'TAG1',
                command: 'OK',
                attributes: [
                    {
                        type: 'ATOM',
                        value: '',
                        section: [
                            {
                                type: 'ATOM',
                                value: 'METADATA'
                            },
                            {
                                type: 'ATOM',
                                value: 'LONGENTRIES'
                            },
                            {
                                type: 'ATOM',
                                value: '2199'
                            }
                        ]
                    },
                    {
                        type: 'TEXT',
                        value: 'GETMETADATA complete'
                    }
                ]
            });

            // RFC4467 defines URLMECH.  Included because of the example
            // third atom involves base64-encoding which is somewhat unusual
            expect(imapHandler.parser('TAG1 OK [URLMECH INTERNAL XSAMPLE=P34OKhO7VEkCbsiYY8rGEg==] done')).to.deep.equal({
                tag: 'TAG1',
                command: 'OK',
                attributes: [
                    {
                        type: 'ATOM',
                        value: '',
                        section: [
                            {
                                type: 'ATOM',
                                value: 'URLMECH'
                            },
                            {
                                type: 'ATOM',
                                value: 'INTERNAL'
                            },
                            {
                                type: 'ATOM',
                                value: 'XSAMPLE=P34OKhO7VEkCbsiYY8rGEg=='
                            }
                        ]
                    },
                    {
                        type: 'TEXT',
                        value: 'done'
                    }
                ]
            });

            // RFC2221 defines REFERRAL where the argument is an imapurl
            // (defined by RFC2192 which is obsoleted by RFC5092) which
            // is significantly more complicated than the rest of the IMAP
            // grammar and which was based on the RFC2060 grammar where
            // resp_text_code included:
            //   atom [SPACE 1*<any TEXT_CHAR except ']'>]
            // So this is just a test case of our explicit special-casing
            // of REFERRAL.
            expect(imapHandler.parser('TAG1 NO [REFERRAL IMAP://user;AUTH=*@SERVER2/] Remote Server')).to.deep.equal({
                tag: 'TAG1',
                command: 'NO',
                attributes: [
                    {
                        type: 'ATOM',
                        value: '',
                        section: [
                            {
                                type: 'ATOM',
                                value: 'REFERRAL'
                            },
                            {
                                type: 'ATOM',
                                value: 'IMAP://user;AUTH=*@SERVER2/'
                            }
                        ]
                    },
                    {
                        type: 'TEXT',
                        value: 'Remote Server'
                    }
                ]
            });

            // PERMANENTFLAGS is from RFC3501.  Its syntax is also very
            // similar to BADCHARSET, except BADCHARSET has astrings
            // inside the list.
            expect(imapHandler.parser('* OK [PERMANENTFLAGS (de:hacking $label kt-evalution [css3-page] \\*)] Flags permitted.')).to.deep.equal({
                tag: '*',
                command: 'OK',
                attributes: [
                    {
                        type: 'ATOM',
                        value: '',
                        section: [
                            // keep indentation
                            {
                                type: 'ATOM',
                                value: 'PERMANENTFLAGS'
                            },
                            [
                                {
                                    type: 'ATOM',
                                    value: 'de:hacking'
                                },
                                {
                                    type: 'ATOM',
                                    value: '$label'
                                },
                                {
                                    type: 'ATOM',
                                    value: 'kt-evalution'
                                },
                                {
                                    type: 'ATOM',
                                    value: '[css3-page]'
                                },
                                {
                                    type: 'ATOM',
                                    value: '\\*'
                                }
                            ]
                        ]
                    },
                    {
                        type: 'TEXT',
                        value: 'Flags permitted.'
                    }
                ]
            });

            // COPYUID is from RFC4315 and included the previously failing
            // parsing situation of a sequence terminated by ']' rather than
            // whitespace.
            expect(imapHandler.parser('TAG1 OK [COPYUID 4 1417051618:1417051620 1421730687:1421730689] COPY completed')).to.deep.equal({
                tag: 'TAG1',
                command: 'OK',
                attributes: [
                    {
                        type: 'ATOM',
                        value: '',
                        section: [
                            {
                                type: 'ATOM',
                                value: 'COPYUID'
                            },
                            {
                                type: 'ATOM',
                                value: '4'
                            },
                            {
                                type: 'SEQUENCE',
                                value: '1417051618:1417051620'
                            },
                            {
                                type: 'SEQUENCE',
                                value: '1421730687:1421730689'
                            }
                        ]
                    },
                    {
                        type: 'TEXT',
                        value: 'COPY completed'
                    }
                ]
            });

            // MODIFIED is from RFC4551 and is basically the same situation
            // as the COPYUID case, but in this case our example sequences
            // have commas in them.  (Note that if there was no comma, the
            // '7,9' payload would end up an ATOM.)
            expect(imapHandler.parser('TAG1 OK [MODIFIED 7,9] Conditional STORE failed')).to.deep.equal({
                tag: 'TAG1',
                command: 'OK',
                attributes: [
                    {
                        type: 'ATOM',
                        value: '',
                        section: [
                            {
                                type: 'ATOM',
                                value: 'MODIFIED'
                            },
                            {
                                type: 'SEQUENCE',
                                value: '7,9'
                            }
                        ]
                    },
                    {
                        type: 'TEXT',
                        value: 'Conditional STORE failed'
                    }
                ]
            });
        });
    });

    describe('ATOM Partial', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD BODY[]<0>').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'BODY',
                    section: [],
                    partial: [0]
                }
            ]);
            expect(imapHandler.parser('TAG1 CMD BODY[]<12.45>').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'BODY',
                    section: [],
                    partial: [12, 45]
                }
            ]);
            expect(imapHandler.parser('TAG1 CMD BODY[HEADER.FIELDS (Subject From)]<12.45>').attributes).to.deep.equal([
                {
                    type: 'ATOM',
                    value: 'BODY',
                    section: [
                        // keep indentation
                        {
                            type: 'ATOM',
                            value: 'HEADER.FIELDS'
                        },
                        [
                            {
                                type: 'ATOM',
                                value: 'Subject'
                            },
                            {
                                type: 'ATOM',
                                value: 'From'
                            }
                        ]
                    ],
                    partial: [12, 45]
                }
            ]);
        });

        it('should fail', function() {
            expect(function() {
                imapHandler.parser('TAG1 CMD KODY<0.123>');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD BODY[]<01>');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD BODY[]<0.01>');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD BODY[]<0.1.>');
            }).to.throw(Error);
        });
    });

    describe('SEQUENCE', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('TAG1 CMD *:4,5:7 TEST').attributes).to.deep.equal([
                {
                    type: 'SEQUENCE',
                    value: '*:4,5:7'
                },
                {
                    type: 'ATOM',
                    value: 'TEST'
                }
            ]);

            expect(imapHandler.parser('TAG1 CMD 1:* TEST').attributes).to.deep.equal([
                {
                    type: 'SEQUENCE',
                    value: '1:*'
                },
                {
                    type: 'ATOM',
                    value: 'TEST'
                }
            ]);

            expect(imapHandler.parser('TAG1 CMD *:4 TEST').attributes).to.deep.equal([
                {
                    type: 'SEQUENCE',
                    value: '*:4'
                },
                {
                    type: 'ATOM',
                    value: 'TEST'
                }
            ]);
        });

        it('should fail', function() {
            expect(function() {
                imapHandler.parser('TAG1 CMD *:4,5:');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD *:4,5:TEST TEST');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD *:4,5: TEST');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD *4,5 TEST');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD *,5 TEST');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD 5,* TEST');
            }).to.throw(Error);

            expect(function() {
                imapHandler.parser('TAG1 CMD 5, TEST');
            }).to.throw(Error);
        });
    });

    describe('Escaped quotes', function() {
        it('should succeed', function() {
            expect(imapHandler.parser('* 331 FETCH (ENVELOPE ("=?ISO-8859-1?Q?\\"G=FCnter__Hammerl\\"?="))').attributes).to.deep.equal([
                // keep indentation
                {
                    type: 'ATOM',
                    value: 'FETCH'
                },
                [
                    // keep indentation
                    {
                        type: 'ATOM',
                        value: 'ENVELOPE'
                    },
                    [
                        {
                            type: 'STRING',
                            value: '=?ISO-8859-1?Q?"G=FCnter__Hammerl"?='
                        }
                    ]
                ]
            ]);
        });
    });

    describe('MimeTorture', function() {
        it('should parse mimetorture input', function() {
            let parsed;
            expect(function() {
                parsed = imapHandler.parser(mimetorture.input);
            }).to.not.throw(Error);
            expect(parsed).to.deep.equal(mimetorture.output);
        });
    });
});
