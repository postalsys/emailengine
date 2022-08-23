/* eslint no-unused-expressions: 0, prefer-arrow-callback: 0, no-console: 0 */
/* global after */

'use strict';

let config = require('wild-config');
//let testServer = require('./test-server.js');
let testClient = require('./test-client.js');
let exec = require('child_process').exec;

let chai = require('chai');
let chunks = require('./fixtures/chunks');
let expect = chai.expect;
chai.config.includeStack = true;

describe('IMAP Protocol integration tests', function () {
    this.timeout(10000); // eslint-disable-line no-invalid-this
    let port = 9993;

    beforeEach(function (done) {
        exec(__dirname + '/prepare.sh ' + config.dbs.dbname, { cwd: __dirname }, (err, stdout, stderr) => {
            if (process.env.DEBUG_CONSOLE) {
                console.log(stdout.toString());
                console.log(stderr.toString());
            }
            if (err) {
                return done(err);
            }
            done();
        });
    });

    afterEach(function (done) {
        done();
    });

    after(function (done) {
        //mongo "$DBNAME" --eval "db.getCollectionNames().forEach(function(key){db[key].deleteMany({});})" > /dev/null
        exec('mongo ' + config.dbs.dbname + ' --eval "db.getCollectionNames().forEach(function(key){db[key].deleteMany({});})"', err => {
            if (err) {
                return done(err);
            }
            done();
        });
    });

    describe('CAPABILITY', function () {
        it('should list capabilites', function (done) {
            let cmds = ['T1 CAPABILITY', 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^\* CAPABILITY IMAP4rev1 /m.test(resp.toString())).to.be.true;
                    expect(/^T1 OK/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });
    });

    describe('LOGIN', function () {
        /*
        let stlsServer;
        let stlsPort;
        let txtServer;
        let txtPort;
        */

        beforeEach(function (done) {
            /*
            stlsServer = testServer({
                secure: false,
                logger: false // remove to print IMAP traffic to console
            });

            txtServer = testServer({
                secure: false,
                ignoreSTARTTLS: true,
                logger: false // remove to print IMAP traffic to console
            });

            stlsServer.listen(function() {
                stlsPort = stlsServer.server.address().port;
                txtServer.listen(function() {
                    txtPort = txtServer.server.address().port;
                    done();
                });
            });
            */
            done();
        });

        afterEach(function (done) {
            /*
            stlsServer.close(function() {
                txtServer.close(done);
            });
            */
            done();
        });

        it('should authenticate', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^T1 OK/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });
        /*
        it('should authenticate using STARTTLS', function(done) {
            let cmds = ['T1 STARTTLS', 'T2 LOGIN testuser pass', 'T3 LOGOUT'];

            testClient(
                {
                    port: stlsPort,
                    commands: cmds,
                    secure: false
                },
                function(resp) {
                    expect(/^T2 OK/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });

        it('should fail auth without STARTTLS', function(done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LOGOUT'];

            testClient(
                {
                    port: stlsPort,
                    commands: cmds,
                    secure: false
                },
                function(resp) {
                    expect(/^T1 BAD/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });

        it('should authenticate without using STARTTLS', function(done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LOGOUT'];

            testClient(
                {
                    port: txtPort,
                    commands: cmds,
                    secure: false
                },
                function(resp) {
                    expect(/^T1 OK/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });
*/
        it('should fail authentication', function (done) {
            let cmds = ['T1 LOGIN testuser wrongpass', 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^T1 NO/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });
    });

    describe('AUTHENTICATE PLAIN', function () {
        it('should authenticate', function (done) {
            let cmds = ['T1 AUTHENTICATE PLAIN', Buffer.from('\x00testuser\x00pass', 'utf-8').toString('base64'), 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^T1 OK/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });

        it('should authenticate using SASL-IR', function (done) {
            let cmds = ['T1 AUTHENTICATE PLAIN ' + Buffer.from('\x00testuser\x00pass', 'utf-8').toString('base64'), 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^T1 OK/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });

        it('should fail authentication', function (done) {
            let cmds = ['T1 AUTHENTICATE PLAIN', Buffer.from('\x00testuser\x00wrongpass', 'utf-8').toString('base64'), 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^T1 NO/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });

        it('should reject client token', function (done) {
            let cmds = ['T1 AUTHENTICATE PLAIN', Buffer.from('\x00testuser\x00pass\x00token', 'utf-8').toString('base64'), 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^T1 BAD/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });

        it('should authenticate with client token', function (done) {
            let cmds = ['T1 AUTHENTICATE PLAIN-CLIENTTOKEN', Buffer.from('\x00testuser\x00pass\x00token', 'utf-8').toString('base64'), 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^T1 OK/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });
    });

    describe('NAMESPACE', function () {
        it('should list namespaces', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 NAMESPACE', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    expect(/^\* NAMESPACE \(\("" "\/"\)\) NIL NIL$/m.test(resp.toString())).to.be.true;
                    expect(/^T2 OK/m.test(resp.toString())).to.be.true;
                    done();
                }
            );
        });
    });

    describe('LIST', function () {
        it('should list delimiter', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LIST "" ""', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LIST /gm).length).to.equal(1);
                    expect(resp.indexOf('\r\n* LIST (\\Noselect) "/" "/"\r\n') >= 0).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should list all mailboxes', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LIST "" "*"', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LIST /gm).length).to.equal(6);
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "INBOX"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\Noselect \\HasChildren) "/" "[Gmail]"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should list all mailboxes using XLIST', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 XLIST "" "*"', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* XLIST /gm).length).to.equal(6);
                    expect(resp.indexOf('\r\n* XLIST (\\HasNoChildren \\Inbox) "/" "Inbox"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* XLIST (\\Noselect \\HasChildren) "/" "[Gmail]"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* XLIST (\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should list first level mailboxes', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LIST "" "%"', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LIST /gm).length).to.equal(5);
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "INBOX"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\Noselect \\HasChildren) "/" "[Gmail]"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.false;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should list second level mailboxes', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LIST "" "[Gmail]/%"', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LIST /gm).length).to.equal(1);
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren \\Sent) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('LSUB', function () {
        it('should list all mailboxes', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LSUB "" "*"', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LSUB /gm).length).to.equal(5);
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "INBOX"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should list first level mailboxes', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LSUB "" "%"', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LSUB /gm).length).to.equal(4);
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "INBOX"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.false;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should list second level mailboxes', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 LSUB "" "[Gmail]/%"', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LSUB /gm).length).to.equal(1);
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('CREATE', function () {
        it('should create new mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 CREATE testfolder', 'T3 CREATE parent/child', 'T4 CREATE testfolder', 'T5 LIST "" "*"', 'T6 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    expect(/^T4 NO \[ALREADYEXISTS\]/m.test(resp)).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\Noselect \\HasChildren) "/" "parent"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "parent/child"\r\n') >= 0).to.be.true;
                    done();
                }
            );
        });
    });

    describe('RENAME', function () {
        it('should rename existing mailbox', function (done) {
            let cmds = [
                'T1 LOGIN testuser pass',
                'T2 CREATE testfolder',
                'T3 RENAME testfolder parent/child',
                'T4 RENAME testfolder other',
                'T5 LIST "" "*"',
                'T6 LOGOUT'
            ];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    expect(/^T4 NO \[NONEXISTENT\]/m.test(resp)).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.false;
                    expect(resp.indexOf('\r\n* LIST (\\Noselect \\HasChildren) "/" "parent"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "parent/child"\r\n') >= 0).to.be.true;
                    done();
                }
            );
        });
    });

    describe('DELETE', function () {
        it('should delete existing mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 CREATE testfolder', 'T3 DELETE testfolder', 'T4 DELETE testfolder', 'T5 LIST "" "*"', 'T6 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    expect(/^T4 NO \[NONEXISTENT\]/m.test(resp)).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.false;
                    done();
                }
            );
        });

        it('should disconnect deleted mailbox clients', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 CREATE testfolder', 'T3 SELECT testfolder', 'T4 DELETE testfolder'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    expect(resp.indexOf('\r\n* BYE') >= 0).to.be.true;
                    done();
                }
            );
        });
    });

    describe('APPEND', function () {
        this.timeout(60000); // eslint-disable-line no-invalid-this

        it('should fail appending to nonexistent mailbox', function (done) {
            let message = Buffer.from('From: sender <sender@example.com>\r\nTo: receiver@example.com\r\nSubject: HELLO!\r\n\r\nWORLD!');
            let cmds = ['T1 LOGIN testuser pass', 'T2 APPEND zzz {' + message.length + '}\r\n' + message.toString('binary'), 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T2 NO/m.test(resp)).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.false;
                    done();
                }
            );
        });

        it('should append to mailbox', function (done) {
            let message = Buffer.from('From: sender <sender@example.com>\r\nTo: receiver@example.com\r\nSubject: HELLO!\r\n\r\nWORLD!');
            let cmds = ['T1 LOGIN testuser pass', 'T2 APPEND INBOX {' + message.length + '}\r\n' + message.toString('binary'), 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.false;
                    done();
                }
            );
        });

        it('should append to mailbox with optional arguments', function (done) {
            let message = Buffer.from('From: sender <sender@example.com>\r\nTo: receiver@example.com\r\nSubject: HELLO!\r\n\r\nWORLD!');
            let cmds = [
                'T1 LOGIN testuser pass',
                'T2 APPEND INBOX (MyFlag) "14-Sep-2013 21:22:28 -0300" {' + message.length + '}\r\n' + message.toString('binary'),
                'T3 LOGOUT'
            ];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.false;
                    expect(/^[^\s]+ BAD/m.test(resp)).to.be.false;
                    done();
                }
            );
        });

        it('should append large file in chunks', function (done) {
            let lchunks = [].concat(chunks);
            let message = lchunks.join('');

            let cmds = [
                'T1 LOGIN testuser pass',
                'T2 APPEND INBOX (Seen $NotJunk NotJunk) "20-Oct-2015 09:57:08 +0300" {' + message.length + '}',
                lchunks,
                'T3 LOGOUT'
            ];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    //debug: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    expect(resp.indexOf('\r\n* LIST (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.false;
                    expect(/^[^\s]+ BAD/m.test(resp)).to.be.false;
                    done();
                }
            );
        });
    });

    describe('SELECT', function () {
        it('should not select nonexistent mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT zzz', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T2 NO/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should not select existing mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^\* FLAGS /m.test(resp)).to.be.true;
                    expect(/^\* OK \[PERMANENTFLAGS /m.test(resp)).to.be.true;
                    expect(/^\* OK \[UIDVALIDITY \d+\]/m.test(resp)).to.be.true;
                    expect(/^\* \d+ EXISTS$/m.test(resp)).to.be.true;
                    expect(/^\* \d+ RECENT$/m.test(resp)).to.be.true;
                    expect(/^\* OK \[UIDNEXT \d+\]/m.test(resp)).to.be.true;
                    expect(/^T2 OK \[READ-WRITE\]/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('COPY', function () {
        it('should not copy to nonexistent mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 COPY 1:* zzz', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T3 NO/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should copy to selected mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 COPY 1:* "[Gmail]/Sent Mail"', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('STATUS', function () {
        it('should error on nonexistent mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 STATUS zzz (UIDNEXT MESSAGES)', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T2 NO/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should return status response', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 STATUS INBOX (UIDNEXT MESSAGES HIGHESTMODSEQ)', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^\* STATUS INBOX \(UIDNEXT \d+ MESSAGES \d+ HIGHESTMODSEQ \d+\)$/m.test(resp)).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('ENABLE', function () {
        it('should not enable anything', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 ENABLE X-TEST', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^\* ENABLED$/m.test(resp)).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should enable CONDSTORE', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 ENABLE CONDSTORE', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^\* ENABLED CONDSTORE$/m.test(resp)).to.be.true;
                    expect(/^T2 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('CLOSE', function () {
        it('should error if not in selected state', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 CLOSE', 'T3 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T2 BAD/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should close mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 CLOSE', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('UNSELECT', function () {
        it('should close mailbox', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 UNSELECT', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('ID', function () {
        it('should return ID info', function (done) {
            let cmds = ['T1 ID NIL', 'T2 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(/^\* ID \("name"/m.test(resp)).to.be.true;
                    expect(/^T1 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('STORE', function () {
        it('should set flags', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 STORE 1:* FLAGS (MyFlag1 MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(FLAGS \(MyFlag1 MyFlag2\)\)$/gm).length).to.equal(6);
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should add flags', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 STORE 1:* +FLAGS (MyFlag1 MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(FLAGS \(MyFlag1 MyFlag2\)\)$/gm).length).to.equal(4);
                    expect(resp.match(/^\* \d+ FETCH \(FLAGS \(\\Seen MyFlag1 MyFlag2\)\)$/gm).length).to.equal(2);
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should remove flags', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 STORE 1:* -FLAGS (\\Seen MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(FLAGS \(\)\)$/gm).length).to.equal(2);
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should set some flags with modifier', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 STORE 1:* (UNCHANGEDSINCE 99) FLAGS (MyFlag1 MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(FLAGS \(MyFlag1 MyFlag2\) MODSEQ \(\d+\)\)$/gm).length).to.equal(4);
                    expect(/\[MODIFIED [\d,:]+\]/.test(resp)).to.be.true;
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should set flags with modifier', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 STORE 1:* (UNCHANGEDSINCE 100000) FLAGS (MyFlag1 MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(FLAGS \(MyFlag1 MyFlag2\) MODSEQ \(\d+\)\)$/gm).length).to.equal(6);
                    expect(/MODIFIED/.test(resp)).to.be.false;
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('UID STORE', function () {
        it('should set flags', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 UID STORE 1:* FLAGS (MyFlag1 MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(UID \d+ FLAGS \(MyFlag1 MyFlag2\)\)$/gm).length).to.equal(6);
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should add flags', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 UID STORE 1:* +FLAGS (MyFlag1 MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(UID \d+ FLAGS \(MyFlag1 MyFlag2\)\)$/gm).length).to.equal(4);
                    expect(resp.match(/^\* \d+ FETCH \(UID \d+ FLAGS \(\\Seen MyFlag1 MyFlag2\)\)$/gm).length).to.equal(2);
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should remove flags', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 UID STORE 1:* -FLAGS (\\Seen MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(UID \d+ FLAGS \(\)\)$/gm).length).to.equal(2);
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should set some flags with modifier', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 UID STORE 1:* (UNCHANGEDSINCE 99) FLAGS (MyFlag1 MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(UID \d+ FLAGS \(MyFlag1 MyFlag2\) MODSEQ \(\d+\)\)$/gm).length).to.equal(4);
                    expect(/\[MODIFIED [\d,:]+\]/.test(resp)).to.be.true;
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should set some flags with modifier', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 UID STORE 1:* (UNCHANGEDSINCE 10000) FLAGS (MyFlag1 MyFlag2)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ FETCH \(UID \d+ FLAGS \(MyFlag1 MyFlag2\) MODSEQ \(\d+\)\)$/gm).length).to.equal(6);
                    expect(/MODIFIED/.test(resp)).to.be.false;
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('SUBSCRIBE', function () {
        it('should subscribe to mailbox', function (done) {
            let cmds = [
                'T1 LOGIN testuser pass',
                'T2 CREATE testfolder',
                'T3 UNSUBSCRIBE testfolder',
                'T4 SUBSCRIBE testfolder',
                'T5 LSUB "" "*"',
                'T6 LOGOUT'
            ];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LSUB /gm).length).to.equal(6);
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "INBOX"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.true;
                    expect(/^T4 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('UNSUBSCRIBE', function () {
        it('should unsubscribe from mailbox', function (done) {
            let cmds = [
                'T1 LOGIN testuser pass',
                'T2 CREATE testfolder',
                'T3 SUBSCRIBE testfolder',
                'T4 UNSUBSCRIBE testfolder',
                'T5 LSUB "" "*"',
                'T6 LOGOUT'
            ];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* LSUB /gm).length).to.equal(5);
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "INBOX"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "[Gmail]/Sent Mail"\r\n') >= 0).to.be.true;
                    expect(resp.indexOf('\r\n* LSUB (\\HasNoChildren) "/" "testfolder"\r\n') >= 0).to.be.false;
                    expect(/^T4 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('EXPUNGE', function () {
        // EXPUNGE is a NO OP with autoexpunge
        it('should expunge all deleted messages', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 STORE 2:* +FLAGS (\\Deleted)', 'T4 EXPUNGE', 'T6 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ EXPUNGE/gm).length).to.equal(5);
                    expect(/^T4 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('UID EXPUNGE', function () {
        // UID EXPUNGE is a NO OP with autoexpunge
        it('should expunge specific messages', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 STORE 1:* +FLAGS (\\Deleted)', 'T4 UID EXPUNGE 103,105', 'T5 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* \d+ EXPUNGE/gm).length).to.equal(2);
                    expect(resp.match(/^\* 3 EXPUNGE/gm).length).to.equal(1);
                    expect(resp.match(/^\* 4 EXPUNGE/gm).length).to.equal(1);
                    expect(/^T4 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });

    describe('FETCH command', function () {
        it('should list by UID', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 UID FETCH 103 (FLAGS)', 'T4 FETCH 3 (FLAGS)', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.slice(/\n/).indexOf('* 3 FETCH (FLAGS (\\Seen) UID 103)') >= 0).to.be.true; // UID FETCH FLAGS
                    expect(resp.slice(/\n/).indexOf('* 3 FETCH (FLAGS (\\Seen))') >= 0).to.be.true; // FETCH FLAGS
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should list with MODSEQ', function (done) {
            let cmds = [
                'T1 LOGIN testuser pass',
                'T2 SELECT INBOX',
                'T3 UID FETCH 103 (FLAGS) (CHANGEDSINCE 1)',
                'T4 FETCH 3 (FLAGS) (CHANGEDSINCE 1)',
                'T5 UID FETCH 103 (FLAGS) (CHANGEDSINCE 10000)',
                'T6 FETCH 3 (FLAGS) (CHANGEDSINCE 10000)',
                'T7 LOGOUT'
            ];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.slice(/\n/).indexOf('* 3 FETCH (FLAGS (\\Seen) UID 103 MODSEQ (3))') >= 0).to.be.true; // UID FETCH FLAGS
                    expect(resp.slice(/\n/).indexOf('* 3 FETCH (FLAGS (\\Seen) MODSEQ (3))') >= 0).to.be.true; // FETCH FLAGS
                    expect(resp.match(/^\* \d+ FETCH/gm).length).to.equal(2);
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    expect(/^T4 OK/m.test(resp)).to.be.true;
                    expect(/^T5 OK/m.test(resp)).to.be.true;
                    expect(/^T6 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        describe('Multiple values', function () {
            it('should list mixed data', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 1:* (UID BODYSTRUCTURE ENVELOPE)', 'T4 LOGOUT'];
                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp
                                .slice(/\n/)
                                .indexOf(
                                    '* 1 FETCH (UID 101 BODYSTRUCTURE ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 6 1 NIL NIL NIL NIL) ENVELOPE (NIL "test" ((NIL NIL "sender" "example.com")) ((NIL NIL "sender" "example.com")) ((NIL NIL "sender" "example.com")) ((NIL NIL "to" "example.com")) ((NIL NIL "cc" "example.com")) NIL NIL NIL))'
                                ) >= 0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });
        });

        describe('BODY[] marks message as seen', function () {
            it('should list raw message', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 3 BODY[2.HEADER]', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();

                        expect(
                            resp.indexOf(
                                '\n* 3 FETCH (BODY[2.HEADER] {71}\r\n' +
                                    'MIME-Version: 1.0\r\n' +
                                    'From: andris@kreata.ee\r\n' +
                                    'To: andris@pangalink.net\r\n' +
                                    '\r\n' +
                                    ' FLAGS (\\Seen))\r\n'
                            ) >= 0
                        ).to.be.true;

                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });
        });

        describe('UID', function () {
            it('should return correct UID', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 3 UID', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();

                        expect(resp.indexOf('\n* 3 FETCH (UID 103)\r\n') >= 0).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;

                        done();
                    }
                );
            });
        });

        describe('FLAGS', function () {
            it('should return corretc FLAGS', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 3 FLAGS', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();

                        expect(resp.indexOf('\n* 3 FETCH (FLAGS (\\Seen))\r\n') >= 0).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;

                        done();
                    }
                );
            });
        });

        describe('BODYSTRUCTURE', function () {
            it('should list bodystructure object', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 3 BODYSTRUCTURE', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf(
                                '\n* 3 FETCH (BODYSTRUCTURE (("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 107 (NIL "" ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "pangalink.net")) NIL NIL "<test1>" NIL) ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 14 0 NIL NIL NIL NIL) 5 NIL NIL NIL NIL)("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 85 (NIL "" ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "pangalink.net")) NIL NIL NIL NIL) ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 14 0 NIL NIL NIL NIL) 4 NIL NIL NIL NIL)("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "QUOTED-PRINTABLE" 21 0 NIL NIL NIL NIL) "MIXED" ("BOUNDARY" "----mailcomposer-?=_1-1328088797399") NIL NIL NIL))\r\n'
                            ) >= 0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });
        });

        describe('ENVELOPE', function () {
            it('should list envelope object', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 1:* ENVELOPE', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf(
                                '\n* 3 FETCH (ENVELOPE (NIL "" ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "kreata.ee")) ((NIL NIL "andris" "tr.ee")) NIL NIL NIL "<testmessage-for-bug>;"))\r\n'
                            ) >= 0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });
        });

        describe('BODY', function () {
            it('should return BODY', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 1 BODY', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(resp.indexOf('\n* 1 FETCH (BODY ("TEXT" "PLAIN" NIL NIL NIL "7BIT" 6 1))\r\n') >= 0).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return BODY[]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 BODY.PEEK[]', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf(
                                '\r\n* 4 FETCH (BODY[] {97}\r\nfrom: sender@example.com\r\nto: to@example.com\r\ncc: cc@example.com\r\nsubject: test\r\n\r\nHello World!\r\n)\r\n'
                            ) >= 0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return partial BODY[]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 BODY.PEEK[]<4.5>', 'T4 FETCH 4 BODY.PEEK[]<4.10000>', 'T5 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(resp.indexOf('\n* 4 FETCH (BODY[]<4> {5}\r\n: sen)\r\n') >= 0).to.be.true;
                        expect(
                            resp.indexOf(
                                '\n* 4 FETCH (BODY[]<4> {93}\r\n: sender@example.com\r\nto: to@example.com\r\ncc: cc@example.com\r\nsubject: test\r\n\r\nHello World!\r\n)\r\n'
                            ) >= 0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        expect(/^T4 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return partial BODY[1]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 3 BODY.PEEK[1]', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf(
                                '\r\n* 3 FETCH (BODY[1] {107}\r\nMIME-Version: 1.0\r\nFrom: andris@kreata.ee\r\nTo: andris@pangalink.net\r\nIn-Reply-To: <test1>\r\n\r\nHello world 1!)\r\n'
                            ) >= 0
                        ).to.be.true;

                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return BODY[HEADER]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 BODY.PEEK[HEADER]', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf(
                                '\r\n* 4 FETCH (BODY[HEADER] {83}\r\nfrom: sender@example.com\r\nto: to@example.com\r\ncc: cc@example.com\r\nsubject: test\r\n\r\n)\r\n'
                            ) >= 0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return BODY[HEADER.FIELDS]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 BODY.PEEK[HEADER.FIELDS (From Cc)]', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf('\r\n* 4 FETCH (BODY[HEADER.FIELDS (From Cc)] {48}\r\nfrom: sender@example.com\r\ncc: cc@example.com\r\n\r\n)\r\n') >=
                                0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return BODY[HEADER.FIELDS.NOT]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 BODY.PEEK[HEADER.FIELDS.NOT (From Cc)]', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(resp.indexOf('\r\n* 4 FETCH (BODY[HEADER.FIELDS.NOT (From Cc)] {37}\r\nto: to@example.com\r\nsubject: test\r\n\r\n)\r\n') >= 0)
                            .to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return BODY[TEXT]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 BODY.PEEK[TEXT]', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(resp.indexOf('\r\n* 4 FETCH (BODY[TEXT] {14}\r\nHello World!\r\n)\r\n') >= 0).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return BODY[x.HEADER]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 3 BODY.PEEK[1.HEADER]', 'T4 FETCH 3 BODY.PEEK[2.HEADER]', 'T5 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();

                        expect(
                            resp.indexOf(
                                '\n* 3 FETCH (BODY[1.HEADER] {93}\r\n' +
                                    'MIME-Version: 1.0\r\n' +
                                    'From: andris@kreata.ee\r\n' +
                                    'To: andris@pangalink.net\r\n' +
                                    'In-Reply-To: <test1>\r\n' +
                                    '\r\n' +
                                    ')\r\n'
                            ) >= 0
                        ).to.be.true;

                        expect(
                            resp.indexOf(
                                '\n* 3 FETCH (BODY[2.HEADER] {71}\r\n' +
                                    'MIME-Version: 1.0\r\n' +
                                    'From: andris@kreata.ee\r\n' +
                                    'To: andris@pangalink.net\r\n' +
                                    '\r\n' +
                                    ')\r\n'
                            ) >= 0
                        ).to.be.true;

                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        expect(/^T4 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return BODY[1.MIME]', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 3 BODY.PEEK[1.MIME]', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf('\r\n* 3 FETCH (BODY[1.MIME] {65}\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: 7bit\r\n\r\n)\r\n') >=
                                0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });
        });

        describe('RFC822', function () {
            it('should return RFC822', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 RFC822', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf(
                                '\r\n* 4 FETCH (RFC822 {97}\r\nfrom: sender@example.com\r\nto: to@example.com\r\ncc: cc@example.com\r\nsubject: test\r\n\r\nHello World!\r\n FLAGS (\\Seen))\r\n'
                            ) >= 0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return RFC822.SIZE', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 RFC822.SIZE', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(resp.indexOf('\r\n* 4 FETCH (RFC822.SIZE 97)\r\n') >= 0).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return RFC822.HEADER', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 RFC822.HEADER', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(
                            resp.indexOf(
                                '\r\n* 4 FETCH (RFC822.HEADER {83}\r\nfrom: sender@example.com\r\nto: to@example.com\r\ncc: cc@example.com\r\nsubject: test\r\n\r\n)\r\n'
                            ) >= 0
                        ).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });

            it('should return RFC822.TEXT', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 4 RFC822.TEXT', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();

                        expect(resp.indexOf('\r\n* 4 FETCH (RFC822.TEXT {14}\r\nHello World!\r\n)\r\n') >= 0).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });
        });

        describe('INTERNALDATE', function () {
            it('should return message internaldate', function (done) {
                let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 FETCH 1 INTERNALDATE', 'T4 LOGOUT'];

                testClient(
                    {
                        commands: cmds,
                        secure: true,
                        port
                    },
                    function (resp) {
                        resp = resp.toString();
                        expect(resp.indexOf('\r\n* 1 FETCH (INTERNALDATE "15-Sep-2013 00:22:28 +0000")\r\n') >= 0).to.be.true;
                        expect(/^T3 OK/m.test(resp)).to.be.true;
                        done();
                    }
                );
            });
        });
    });

    describe('SEARCH command', function () {
        it('should succeed', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 SEARCH ALL', 'T4 UID SEARCH ALL', 'T7 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* SEARCH /gm).length).to.equal(2);
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    expect(/^T4 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should find with FLAGS', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 SEARCH (UNSEEN)', 'T4 UID SEARCH UNSEEN', 'T7 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* SEARCH /gm).length).to.equal(2);
                    expect(/^\* SEARCH 1 4 5 6$/m.test(resp)).to.be.true;
                    expect(/^\* SEARCH 101 104 105 106$/m.test(resp)).to.be.true;
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    expect(/^T4 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });

        it('should find with MODSEQ', function (done) {
            let cmds = ['T1 LOGIN testuser pass', 'T2 SELECT INBOX', 'T3 SEARCH MODSEQ 1000', 'T4 LOGOUT'];

            testClient(
                {
                    commands: cmds,
                    secure: true,
                    port
                },
                function (resp) {
                    resp = resp.toString();
                    expect(resp.match(/^\* SEARCH /gm).length).to.equal(1);
                    expect(/^\* SEARCH 2 \(MODSEQ 5000\)$/m.test(resp)).to.be.true;
                    expect(/^T3 OK/m.test(resp)).to.be.true;
                    done();
                }
            );
        });
    });
});
