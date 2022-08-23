/* eslint indent: 0 */

'use strict';

module.exports = {
    // IMAP response value for Ryan Finnie's MIME Torture Test v1.0
    // Command used: a fetch 1 (ENVELOPE BODYSTRUCTURE FLAGS BODY[])
    input: '* 1 FETCH (FLAGS (\\Seen $eee) ENVELOPE ("23 Oct 2003 23:28:34 -0700" "Ryan Finnie\'s MIME Torture Test v1.0" (("Andris Reinman" NIL "andris" "ekiri.ee")) (("Andris Reinman" NIL "andris" "ekiri.ee")) (("Andris Reinman" NIL "andris" "ekiri.ee")) ((NIL NIL "andmekala" "hot.ee")) NIL NIL NIL "<1066976914.4721.5.camel@localhost>") BODYSTRUCTURE (("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 617 16 NIL NIL NIL NIL)("message" "rfc822" NIL NIL "I\'ll be whatever I wanna do. --Fry" "7bit" 582 ("23 Oct 2003 22:25:56 -0700" "plain jane message" (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066973156.4264.42.camel@localhost>") ("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 311 9 NIL NIL NIL NIL) 18 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL "Would you kindly shut your noise-hole? --Bender" "7bit" 1460 ("23 Oct 2003 23:15:11 -0700" "messages inside messages inside..." (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066976111.4263.74.camel@localhost>") (("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 193 3 NIL NIL NIL NIL)("message" "rfc822" NIL NIL "At the risk of sounding negative, no. --Leela" "7bit" 697 ("23 Oct 2003 23:09:05 -0700" "the original message" (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066975745.4263.70.camel@localhost>") (("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 78 3 NIL NIL NIL NIL)("application" "x-gzip" ("NAME" "foo.gz") NIL NIL "base64" 58 NIL ("attachment" ("filename" "foo.gz")) NIL NIL) "mixed" ("boundary" "=-XFYecI7w+0shpolXq8bb") NIL NIL NIL) 25 NIL ("inline" NIL) NIL NIL) "mixed" ("boundary" "=-9Brg7LoMERBrIDtMRose") NIL NIL NIL) 49 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL "Dirt doesn\'t need luck! --Professor" "7bit" 817 ("23 Oct 2003 22:40:49 -0700" "this message JUST contains an attachment" (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066974048.4264.62.camel@localhost>") ("application" "x-gzip" ("NAME" "blah.gz") NIL "Attachment has identical content to above foo.gz" "base64" 396 NIL ("attachment" ("filename" "blah.gz")) NIL NIL) 17 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL "Hold still, I don\'t have good depth perception! --Leela" "7bit" 1045 ("23 Oct 2003 23:09:16 -0700" "Attachment filename vs. name" (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066975756.4263.70.camel@localhost>") (("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 377 6 NIL NIL NIL NIL)("application" "x-gzip" ("NAME" "blah2.gz") NIL "filename is blah1.gz, name is blah2.gz" "base64" 58 NIL ("attachment" ("filename" "blah1.gz")) NIL NIL) "mixed" ("boundary" "=-1066975756jd02") NIL NIL NIL) 29 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL "Hello little man.  I WILL DESTROY YOU! --Moro" "7bit" 1149 ("23 Oct 2003 23:09:21 -0700" {24}\r\nNo filename? No problem! (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066975761.4263.70.camel@localhost>") (("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 517 10 NIL NIL NIL NIL)("application" "x-gzip" NIL NIL "I\'m getting sick of witty things to say" "base64" 58 NIL ("attachment" NIL) NIL NIL) "mixed" ("boundary" "=-1066975756jd03") NIL NIL NIL) 33 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL "Friends! Help! A guinea pig tricked me! --Zoidberg" "7bit" 896 ("23 Oct 2003 22:40:45 -0700" "html and text, both inline" (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066974044.4264.62.camel@localhost>") (("text" "html" ("CHARSET" "utf-8") NIL NIL "8bit" 327 11 NIL NIL NIL NIL)("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 61 2 NIL NIL NIL NIL) "mixed" ("boundary" "=-ZCKMfHzvHMyK1iBu4kff") NIL NIL NIL) 33 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL "Smeesh! --Amy" "7bit" 642 ("23 Oct 2003 22:41:29 -0700" "text and text, both inline" (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066974089.4265.64.camel@localhost>") (("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 62 2 NIL NIL NIL NIL)("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 68 2 NIL NIL NIL NIL) "mixed" ("boundary" "=-pNc4wtlOIxs8RcX7H/AK") NIL NIL NIL) 24 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL "That\'s not a cigar. Uh... and it\'s not mine. --Hermes" "7bit" 1515 ("23 Oct 2003 22:39:17 -0700" {17}\r\nHTML and... HTML? (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066973957.4263.59.camel@localhost>") (("text" "html" ("CHARSET" "utf-8") NIL NIL "8bit" 824 22 NIL NIL NIL NIL)("text" "html" ("NAME" "htmlfile.html" "CHARSET" "UTF-8") NIL NIL "8bit" 118 6 NIL ("attachment" ("filename" "htmlfile.html")) NIL NIL) "mixed" ("boundary" "=-zxh/IezwzZITiphpcbJZ") NIL NIL NIL) 49 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL {71}\r\nThe spirit is willing, but the flesh is spongy, and\r\n    bruised. --Zapp "7bit" 6643 ("23 Oct 2003 22:23:16 -0700" "smiley!" (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066972996.4264.39.camel@localhost>") ((((("text" "plain" ("charset" "us-ascii") NIL NIL "quoted-printable" 1606 42 NIL NIL NIL NIL)("text" "html" ("charset" "utf-8") NIL NIL "quoted-printable" 2128 54 NIL NIL NIL NIL) "alternative" ("boundary" "=-dHujWM/Xizz57x/JOmDF") NIL NIL NIL)("image" "png" ("name" "smiley-3.png") "<1066971953.4232.15.camel@localhost>" NIL "base64" 1122 NIL ("attachment" ("filename" "smiley-3.png")) NIL NIL) "related" ("type" "multipart/alternative" "boundary" "=-GpwozF9CQ7NdF+fd+vMG") NIL NIL NIL)("image" "gif" ("name" "dot.gif") NIL NIL "base64" 96 NIL ("attachment" ("filename" "dot.gif")) NIL NIL) "mixed" ("boundary" "=-CgV5jm9HAY9VbUlAuneA") NIL NIL NIL)("application" "pgp-signature" ("name" "signature.asc") NIL "This is a digitally signed message part" "7bit" 196 NIL NIL NIL NIL) "signed" ("micalg" "pgp-sha1" "protocol" "application/pgp-signature" "boundary" "=-vH3FQO9a8icUn1ROCoAi") NIL NIL NIL) 177 NIL ("inline" NIL) NIL NIL)("message" "rfc822" NIL NIL "Kittens give Morbo gas. --Morbo" "7bit" 3088 ("23 Oct 2003 22:32:37 -0700" "the PROPER way to do alternative/related" (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) (("Ryan Finnie" NIL "rfinnie" "domain.dom")) ((NIL NIL "bob" "domain.dom")) NIL NIL NIL "<1066973557.4265.51.camel@localhost>") (("text" "plain" ("CHARSET" "US-ASCII") NIL NIL "8bit" 863 22 NIL NIL NIL NIL)(("text" "html" ("CHARSET" "utf-8") NIL NIL "8bit" 1258 22 NIL NIL NIL NIL)("image" "gif" NIL "<1066973340.4232.46.camel@localhost>" NIL "base64" 116 NIL NIL NIL NIL) "related" ("boundary" "=-bFkxH1S3HVGcxi+o/5jG") NIL NIL NIL) "alternative" ("type" "multipart/alternative" "boundary" "=-tyGlQ9JvB5uvPWzozI+y") NIL NIL NIL) 79 NIL ("inline" NIL) NIL NIL) "mixed" ("boundary" "=-qYxqvD9rbH0PNeExagh1") NIL NIL NIL) BODY[] {0}\r\n)',
    output: {
        tag: '*',
        command: '1',
        attributes: [
            {
                type: 'ATOM',
                value: 'FETCH'
            },
            [
                {
                    type: 'ATOM',
                    value: 'FLAGS'
                },
                [
                    {
                        type: 'ATOM',
                        value: '\\Seen'
                    },
                    {
                        type: 'ATOM',
                        value: '$eee'
                    }
                ],
                {
                    type: 'ATOM',
                    value: 'ENVELOPE'
                },
                [
                    {
                        type: 'STRING',
                        value: '23 Oct 2003 23:28:34 -0700'
                    },
                    {
                        type: 'STRING',
                        value: 'Ryan Finnie\'s MIME Torture Test v1.0'
                    },
                    [
                        [
                            {
                                type: 'STRING',
                                value: 'Andris Reinman'
                            },
                            null,
                            {
                                type: 'STRING',
                                value: 'andris'
                            },
                            {
                                type: 'STRING',
                                value: 'ekiri.ee'
                            }
                        ]
                    ],
                    [
                        [
                            {
                                type: 'STRING',
                                value: 'Andris Reinman'
                            },
                            null,
                            {
                                type: 'STRING',
                                value: 'andris'
                            },
                            {
                                type: 'STRING',
                                value: 'ekiri.ee'
                            }
                        ]
                    ],
                    [
                        [
                            {
                                type: 'STRING',
                                value: 'Andris Reinman'
                            },
                            null,
                            {
                                type: 'STRING',
                                value: 'andris'
                            },
                            {
                                type: 'STRING',
                                value: 'ekiri.ee'
                            }
                        ]
                    ],
                    [
                        [
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: 'andmekala'
                            },
                            {
                                type: 'STRING',
                                value: 'hot.ee'
                            }
                        ]
                    ],
                    null,
                    null,
                    null,
                    {
                        type: 'STRING',
                        value: '<1066976914.4721.5.camel@localhost>'
                    }
                ],
                {
                    type: 'ATOM',
                    value: 'BODYSTRUCTURE'
                },
                [
                    [
                        {
                            type: 'STRING',
                            value: 'text'
                        },
                        {
                            type: 'STRING',
                            value: 'plain'
                        },
                        [
                            {
                                type: 'STRING',
                                value: 'CHARSET'
                            },
                            {
                                type: 'STRING',
                                value: 'US-ASCII'
                            }
                        ],
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: '8bit'
                        },
                        {
                            type: 'ATOM',
                            value: '617'
                        },
                        {
                            type: 'ATOM',
                            value: '16'
                        },
                        null,
                        null,
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'I\'ll be whatever I wanna do. --Fry'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '582'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 22:25:56 -0700'
                            },
                            {
                                type: 'STRING',
                                value: 'plain jane message'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066973156.4264.42.camel@localhost>'
                            }
                        ],
                        [
                            {
                                type: 'STRING',
                                value: 'text'
                            },
                            {
                                type: 'STRING',
                                value: 'plain'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'CHARSET'
                                },
                                {
                                    type: 'STRING',
                                    value: 'US-ASCII'
                                }
                            ],
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '8bit'
                            },
                            {
                                type: 'ATOM',
                                value: '311'
                            },
                            {
                                type: 'ATOM',
                                value: '9'
                            },
                            null,
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '18'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'Would you kindly shut your noise-hole? --Bender'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '1460'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 23:15:11 -0700'
                            },
                            {
                                type: 'STRING',
                                value: 'messages inside messages inside...'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066976111.4263.74.camel@localhost>'
                            }
                        ],
                        [
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'plain'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'US-ASCII'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '193'
                                },
                                {
                                    type: 'ATOM',
                                    value: '3'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            [
                                {
                                    type: 'STRING',
                                    value: 'message'
                                },
                                {
                                    type: 'STRING',
                                    value: 'rfc822'
                                },
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: 'At the risk of sounding negative, no. --Leela'
                                },
                                {
                                    type: 'STRING',
                                    value: '7bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '697'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: '23 Oct 2003 23:09:05 -0700'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'the original message'
                                    },
                                    [
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'Ryan Finnie'
                                            },
                                            null,
                                            {
                                                type: 'STRING',
                                                value: 'rfinnie'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'domain.dom'
                                            }
                                        ]
                                    ],
                                    [
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'Ryan Finnie'
                                            },
                                            null,
                                            {
                                                type: 'STRING',
                                                value: 'rfinnie'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'domain.dom'
                                            }
                                        ]
                                    ],
                                    [
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'Ryan Finnie'
                                            },
                                            null,
                                            {
                                                type: 'STRING',
                                                value: 'rfinnie'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'domain.dom'
                                            }
                                        ]
                                    ],
                                    [
                                        [
                                            null,
                                            null,
                                            {
                                                type: 'STRING',
                                                value: 'bob'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'domain.dom'
                                            }
                                        ]
                                    ],
                                    null,
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: '<1066975745.4263.70.camel@localhost>'
                                    }
                                ],
                                [
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'text'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'plain'
                                        },
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'CHARSET'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'US-ASCII'
                                            }
                                        ],
                                        null,
                                        null,
                                        {
                                            type: 'STRING',
                                            value: '8bit'
                                        },
                                        {
                                            type: 'ATOM',
                                            value: '78'
                                        },
                                        {
                                            type: 'ATOM',
                                            value: '3'
                                        },
                                        null,
                                        null,
                                        null,
                                        null
                                    ],
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'application'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'x-gzip'
                                        },
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'NAME'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'foo.gz'
                                            }
                                        ],
                                        null,
                                        null,
                                        {
                                            type: 'STRING',
                                            value: 'base64'
                                        },
                                        {
                                            type: 'ATOM',
                                            value: '58'
                                        },
                                        null,
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'attachment'
                                            },
                                            [
                                                {
                                                    type: 'STRING',
                                                    value: 'filename'
                                                },
                                                {
                                                    type: 'STRING',
                                                    value: 'foo.gz'
                                                }
                                            ]
                                        ],
                                        null,
                                        null
                                    ],
                                    {
                                        type: 'STRING',
                                        value: 'mixed'
                                    },
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'boundary'
                                        },
                                        {
                                            type: 'STRING',
                                            value: '=-XFYecI7w+0shpolXq8bb'
                                        }
                                    ],
                                    null,
                                    null,
                                    null
                                ],
                                {
                                    type: 'ATOM',
                                    value: '25'
                                },
                                null,
                                [
                                    {
                                        type: 'STRING',
                                        value: 'inline'
                                    },
                                    null
                                ],
                                null,
                                null
                            ],
                            {
                                type: 'STRING',
                                value: 'mixed'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'boundary'
                                },
                                {
                                    type: 'STRING',
                                    value: '=-9Brg7LoMERBrIDtMRose'
                                }
                            ],
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '49'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'Dirt doesn\'t need luck! --Professor'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '817'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 22:40:49 -0700'
                            },
                            {
                                type: 'STRING',
                                value: 'this message JUST contains an attachment'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066974048.4264.62.camel@localhost>'
                            }
                        ],
                        [
                            {
                                type: 'STRING',
                                value: 'application'
                            },
                            {
                                type: 'STRING',
                                value: 'x-gzip'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'NAME'
                                },
                                {
                                    type: 'STRING',
                                    value: 'blah.gz'
                                }
                            ],
                            null,
                            {
                                type: 'STRING',
                                value: 'Attachment has identical content to above foo.gz'
                            },
                            {
                                type: 'STRING',
                                value: 'base64'
                            },
                            {
                                type: 'ATOM',
                                value: '396'
                            },
                            null,
                            [
                                {
                                    type: 'STRING',
                                    value: 'attachment'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'filename'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'blah.gz'
                                    }
                                ]
                            ],
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '17'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'Hold still, I don\'t have good depth perception! --Leela'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '1045'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 23:09:16 -0700'
                            },
                            {
                                type: 'STRING',
                                value: 'Attachment filename vs. name'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066975756.4263.70.camel@localhost>'
                            }
                        ],
                        [
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'plain'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'US-ASCII'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '377'
                                },
                                {
                                    type: 'ATOM',
                                    value: '6'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            [
                                {
                                    type: 'STRING',
                                    value: 'application'
                                },
                                {
                                    type: 'STRING',
                                    value: 'x-gzip'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'NAME'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'blah2.gz'
                                    }
                                ],
                                null,
                                {
                                    type: 'STRING',
                                    value: 'filename is blah1.gz, name is blah2.gz'
                                },
                                {
                                    type: 'STRING',
                                    value: 'base64'
                                },
                                {
                                    type: 'ATOM',
                                    value: '58'
                                },
                                null,
                                [
                                    {
                                        type: 'STRING',
                                        value: 'attachment'
                                    },
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'filename'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'blah1.gz'
                                        }
                                    ]
                                ],
                                null,
                                null
                            ],
                            {
                                type: 'STRING',
                                value: 'mixed'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'boundary'
                                },
                                {
                                    type: 'STRING',
                                    value: '=-1066975756jd02'
                                }
                            ],
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '29'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'Hello little man.  I WILL DESTROY YOU! --Moro'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '1149'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 23:09:21 -0700'
                            },
                            {
                                type: 'LITERAL',
                                value: 'No filename? No problem!'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066975761.4263.70.camel@localhost>'
                            }
                        ],
                        [
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'plain'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'US-ASCII'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '517'
                                },
                                {
                                    type: 'ATOM',
                                    value: '10'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            [
                                {
                                    type: 'STRING',
                                    value: 'application'
                                },
                                {
                                    type: 'STRING',
                                    value: 'x-gzip'
                                },
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: 'I\'m getting sick of witty things to say'
                                },
                                {
                                    type: 'STRING',
                                    value: 'base64'
                                },
                                {
                                    type: 'ATOM',
                                    value: '58'
                                },
                                null,
                                [
                                    {
                                        type: 'STRING',
                                        value: 'attachment'
                                    },
                                    null
                                ],
                                null,
                                null
                            ],
                            {
                                type: 'STRING',
                                value: 'mixed'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'boundary'
                                },
                                {
                                    type: 'STRING',
                                    value: '=-1066975756jd03'
                                }
                            ],
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '33'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'Friends! Help! A guinea pig tricked me! --Zoidberg'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '896'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 22:40:45 -0700'
                            },
                            {
                                type: 'STRING',
                                value: 'html and text, both inline'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066974044.4264.62.camel@localhost>'
                            }
                        ],
                        [
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'html'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'utf-8'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '327'
                                },
                                {
                                    type: 'ATOM',
                                    value: '11'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'plain'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'US-ASCII'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '61'
                                },
                                {
                                    type: 'ATOM',
                                    value: '2'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            {
                                type: 'STRING',
                                value: 'mixed'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'boundary'
                                },
                                {
                                    type: 'STRING',
                                    value: '=-ZCKMfHzvHMyK1iBu4kff'
                                }
                            ],
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '33'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'Smeesh! --Amy'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '642'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 22:41:29 -0700'
                            },
                            {
                                type: 'STRING',
                                value: 'text and text, both inline'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066974089.4265.64.camel@localhost>'
                            }
                        ],
                        [
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'plain'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'US-ASCII'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '62'
                                },
                                {
                                    type: 'ATOM',
                                    value: '2'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'plain'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'US-ASCII'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '68'
                                },
                                {
                                    type: 'ATOM',
                                    value: '2'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            {
                                type: 'STRING',
                                value: 'mixed'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'boundary'
                                },
                                {
                                    type: 'STRING',
                                    value: '=-pNc4wtlOIxs8RcX7H/AK'
                                }
                            ],
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '24'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'That\'s not a cigar. Uh... and it\'s not mine. --Hermes'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '1515'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 22:39:17 -0700'
                            },
                            {
                                type: 'LITERAL',
                                value: 'HTML and... HTML?'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066973957.4263.59.camel@localhost>'
                            }
                        ],
                        [
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'html'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'utf-8'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '824'
                                },
                                {
                                    type: 'ATOM',
                                    value: '22'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'html'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'NAME'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'htmlfile.html'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'UTF-8'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '118'
                                },
                                {
                                    type: 'ATOM',
                                    value: '6'
                                },
                                null,
                                [
                                    {
                                        type: 'STRING',
                                        value: 'attachment'
                                    },
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'filename'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'htmlfile.html'
                                        }
                                    ]
                                ],
                                null,
                                null
                            ],
                            {
                                type: 'STRING',
                                value: 'mixed'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'boundary'
                                },
                                {
                                    type: 'STRING',
                                    value: '=-zxh/IezwzZITiphpcbJZ'
                                }
                            ],
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '49'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'LITERAL',
                            value: 'The spirit is willing, but the flesh is spongy, and\r\n    bruised. --Zap'
                        },
                        {
                            type: 'ATOM',
                            value: 'p'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '6643'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 22:23:16 -0700'
                            },
                            {
                                type: 'STRING',
                                value: 'smiley!'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066972996.4264.39.camel@localhost>'
                            }
                        ],
                        [
                            [
                                [
                                    [
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'text'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'plain'
                                            },
                                            [
                                                {
                                                    type: 'STRING',
                                                    value: 'charset'
                                                },
                                                {
                                                    type: 'STRING',
                                                    value: 'us-ascii'
                                                }
                                            ],
                                            null,
                                            null,
                                            {
                                                type: 'STRING',
                                                value: 'quoted-printable'
                                            },
                                            {
                                                type: 'ATOM',
                                                value: '1606'
                                            },
                                            {
                                                type: 'ATOM',
                                                value: '42'
                                            },
                                            null,
                                            null,
                                            null,
                                            null
                                        ],
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'text'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'html'
                                            },
                                            [
                                                {
                                                    type: 'STRING',
                                                    value: 'charset'
                                                },
                                                {
                                                    type: 'STRING',
                                                    value: 'utf-8'
                                                }
                                            ],
                                            null,
                                            null,
                                            {
                                                type: 'STRING',
                                                value: 'quoted-printable'
                                            },
                                            {
                                                type: 'ATOM',
                                                value: '2128'
                                            },
                                            {
                                                type: 'ATOM',
                                                value: '54'
                                            },
                                            null,
                                            null,
                                            null,
                                            null
                                        ],
                                        {
                                            type: 'STRING',
                                            value: 'alternative'
                                        },
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'boundary'
                                            },
                                            {
                                                type: 'STRING',
                                                value: '=-dHujWM/Xizz57x/JOmDF'
                                            }
                                        ],
                                        null,
                                        null,
                                        null
                                    ],
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'image'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'png'
                                        },
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'name'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'smiley-3.png'
                                            }
                                        ],
                                        {
                                            type: 'STRING',
                                            value: '<1066971953.4232.15.camel@localhost>'
                                        },
                                        null,
                                        {
                                            type: 'STRING',
                                            value: 'base64'
                                        },
                                        {
                                            type: 'ATOM',
                                            value: '1122'
                                        },
                                        null,
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'attachment'
                                            },
                                            [
                                                {
                                                    type: 'STRING',
                                                    value: 'filename'
                                                },
                                                {
                                                    type: 'STRING',
                                                    value: 'smiley-3.png'
                                                }
                                            ]
                                        ],
                                        null,
                                        null
                                    ],
                                    {
                                        type: 'STRING',
                                        value: 'related'
                                    },
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'type'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'multipart/alternative'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'boundary'
                                        },
                                        {
                                            type: 'STRING',
                                            value: '=-GpwozF9CQ7NdF+fd+vMG'
                                        }
                                    ],
                                    null,
                                    null,
                                    null
                                ],
                                [
                                    {
                                        type: 'STRING',
                                        value: 'image'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'gif'
                                    },
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'name'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'dot.gif'
                                        }
                                    ],
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'base64'
                                    },
                                    {
                                        type: 'ATOM',
                                        value: '96'
                                    },
                                    null,
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'attachment'
                                        },
                                        [
                                            {
                                                type: 'STRING',
                                                value: 'filename'
                                            },
                                            {
                                                type: 'STRING',
                                                value: 'dot.gif'
                                            }
                                        ]
                                    ],
                                    null,
                                    null
                                ],
                                {
                                    type: 'STRING',
                                    value: 'mixed'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'boundary'
                                    },
                                    {
                                        type: 'STRING',
                                        value: '=-CgV5jm9HAY9VbUlAuneA'
                                    }
                                ],
                                null,
                                null,
                                null
                            ],
                            [
                                {
                                    type: 'STRING',
                                    value: 'application'
                                },
                                {
                                    type: 'STRING',
                                    value: 'pgp-signature'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'name'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'signature.asc'
                                    }
                                ],
                                null,
                                {
                                    type: 'STRING',
                                    value: 'This is a digitally signed message part'
                                },
                                {
                                    type: 'STRING',
                                    value: '7bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '196'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            {
                                type: 'STRING',
                                value: 'signed'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'micalg'
                                },
                                {
                                    type: 'STRING',
                                    value: 'pgp-sha1'
                                },
                                {
                                    type: 'STRING',
                                    value: 'protocol'
                                },
                                {
                                    type: 'STRING',
                                    value: 'application/pgp-signature'
                                },
                                {
                                    type: 'STRING',
                                    value: 'boundary'
                                },
                                {
                                    type: 'STRING',
                                    value: '=-vH3FQO9a8icUn1ROCoAi'
                                }
                            ],
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '177'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    [
                        {
                            type: 'STRING',
                            value: 'message'
                        },
                        {
                            type: 'STRING',
                            value: 'rfc822'
                        },
                        null,
                        null,
                        {
                            type: 'STRING',
                            value: 'Kittens give Morbo gas. --Morbo'
                        },
                        {
                            type: 'STRING',
                            value: '7bit'
                        },
                        {
                            type: 'ATOM',
                            value: '3088'
                        },
                        [
                            {
                                type: 'STRING',
                                value: '23 Oct 2003 22:32:37 -0700'
                            },
                            {
                                type: 'STRING',
                                value: 'the PROPER way to do alternative/related'
                            },
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'Ryan Finnie'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'rfinnie'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            [
                                [
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'bob'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'domain.dom'
                                    }
                                ]
                            ],
                            null,
                            null,
                            null,
                            {
                                type: 'STRING',
                                value: '<1066973557.4265.51.camel@localhost>'
                            }
                        ],
                        [
                            [
                                {
                                    type: 'STRING',
                                    value: 'text'
                                },
                                {
                                    type: 'STRING',
                                    value: 'plain'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'CHARSET'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'US-ASCII'
                                    }
                                ],
                                null,
                                null,
                                {
                                    type: 'STRING',
                                    value: '8bit'
                                },
                                {
                                    type: 'ATOM',
                                    value: '863'
                                },
                                {
                                    type: 'ATOM',
                                    value: '22'
                                },
                                null,
                                null,
                                null,
                                null
                            ],
                            [
                                [
                                    {
                                        type: 'STRING',
                                        value: 'text'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'html'
                                    },
                                    [
                                        {
                                            type: 'STRING',
                                            value: 'CHARSET'
                                        },
                                        {
                                            type: 'STRING',
                                            value: 'utf-8'
                                        }
                                    ],
                                    null,
                                    null,
                                    {
                                        type: 'STRING',
                                        value: '8bit'
                                    },
                                    {
                                        type: 'ATOM',
                                        value: '1258'
                                    },
                                    {
                                        type: 'ATOM',
                                        value: '22'
                                    },
                                    null,
                                    null,
                                    null,
                                    null
                                ],
                                [
                                    {
                                        type: 'STRING',
                                        value: 'image'
                                    },
                                    {
                                        type: 'STRING',
                                        value: 'gif'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: '<1066973340.4232.46.camel@localhost>'
                                    },
                                    null,
                                    {
                                        type: 'STRING',
                                        value: 'base64'
                                    },
                                    {
                                        type: 'ATOM',
                                        value: '116'
                                    },
                                    null,
                                    null,
                                    null,
                                    null
                                ],
                                {
                                    type: 'STRING',
                                    value: 'related'
                                },
                                [
                                    {
                                        type: 'STRING',
                                        value: 'boundary'
                                    },
                                    {
                                        type: 'STRING',
                                        value: '=-bFkxH1S3HVGcxi+o/5jG'
                                    }
                                ],
                                null,
                                null,
                                null
                            ],
                            {
                                type: 'STRING',
                                value: 'alternative'
                            },
                            [
                                {
                                    type: 'STRING',
                                    value: 'type'
                                },
                                {
                                    type: 'STRING',
                                    value: 'multipart/alternative'
                                },
                                {
                                    type: 'STRING',
                                    value: 'boundary'
                                },
                                {
                                    type: 'STRING',
                                    value: '=-tyGlQ9JvB5uvPWzozI+y'
                                }
                            ],
                            null,
                            null,
                            null
                        ],
                        {
                            type: 'ATOM',
                            value: '79'
                        },
                        null,
                        [
                            {
                                type: 'STRING',
                                value: 'inline'
                            },
                            null
                        ],
                        null,
                        null
                    ],
                    {
                        type: 'STRING',
                        value: 'mixed'
                    },
                    [
                        {
                            type: 'STRING',
                            value: 'boundary'
                        },
                        {
                            type: 'STRING',
                            value: '=-qYxqvD9rbH0PNeExagh1'
                        }
                    ],
                    null,
                    null,
                    null
                ],
                {
                    type: 'ATOM',
                    value: 'BODY',
                    section: []
                },
                {
                    type: 'LITERAL',
                    value: ''
                }
            ]
        ]
    }
};
