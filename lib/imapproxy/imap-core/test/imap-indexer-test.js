/* eslint-disable global-require */
/* eslint no-unused-expressions: 0, prefer-arrow-callback: 0 */

'use strict';

const chai = require('chai');
const expect = chai.expect;

//let http = require('http');
const fs = require('fs');
const Indexer = require('../lib/indexer/indexer');
const indexer = new Indexer();

chai.config.includeStack = true;

//const HTTP_PORT = 9998;

const fixtures = {
    simple: {
        eml: fs.readFileSync(__dirname + '/fixtures/simple.eml'),
        tree: require('./fixtures/simple.json')
    },
    mimetorture: {
        eml: fs.readFileSync(__dirname + '/fixtures/mimetorture.eml'),
        tree: require('./fixtures/mimetorture.json')
    }
};

describe('#parseMimeTree', function() {
    it('should parse mime message', function(done) {
        let parsed = indexer.parseMimeTree(fixtures.simple.eml);

        //expect(parsed).to.deep.equal(fixtures.simple.tree);

        parsed = indexer.parseMimeTree(fixtures.mimetorture.eml);

        //expect(parsed).to.deep.equal(fixtures.mimetorture.tree);

        indexer.bodyQuery(parsed, '', (err, data) => {
            expect(err).to.not.exist;

            expect(data.toString('binary').replace(/\r?\n/g, '\n')).to.equal(fixtures.mimetorture.eml.toString('binary').replace(/\r?\n/g, '\n'));
            done();
        });
    });
});

/*
describe('#rebuild', function () {
    let httpServer;

    beforeEach(function (done) {
        httpServer = http.createServer(function (req, res) {
            res.writeHead(200, {
                'Content-Type': 'text/plain'
            });
            if (req.url === '/qp') {
                res.end('<p>Krediitkaardiga on tehtud kulutusi, mida oleks saanud v=C3=B5i pidanud =\r\ntegema muul viisil kui kaardiga. Krediitkaardiga tehtud kulude kohta ei ole=\r\n t=C3=A4htaegselt esitatud aruandlust, kuludokumentidel ei kajastu =\r\npiisavaid selgitusi, mist=C3=B5ttu esineb olulisi piiranguid kulude =\r\nsihip=C3=A4rasuse ja otstarbekuse hindamisel ning kulude p=C3=B5hjendatuse =\r\nkontrollimine on raskendatud.</p>');
            } else {
                res.end('Hello World! '.repeat(20) + 'Bye!');
            }

        });

        httpServer.listen(HTTP_PORT, done);
    });

    afterEach(function (done) {
        httpServer.close(done);
    });


    it('should rebuild using stream', function (done) {
        let message = `Content-Type: multipart/mixed;
 boundary="foo"

--foo
Content-Type: text/plain
Content-Transfer-Encoding: base64
X-Attachment-Stream-Size: 264
X-Attachment-Stream-Url: <http://localhost:${HTTP_PORT}/>

--foo--
`;
        let parsed = indexer.parseMimeTree(message);
        indexer.bodyQuery(parsed, '', (err, data) => {
            expect(err).to.not.exist;
            expect(data.length).to.equal(492);
            done();
        });
    });

    it('should rebuild stream part', function (done) {
        let message = `Content-Type: multipart/mixed;
 boundary="foo"

--foo
Content-Type: text/plain
Content-Transfer-Encoding: base64
X-Attachment-Stream-Size: 264
X-Attachment-Stream-Url: <http://localhost:${HTTP_PORT}/>

--foo--
`;
        let parsed = indexer.parseMimeTree(message);
        indexer.bodyQuery(parsed, {
            path: '1',
            type: ''
        }, (err, data) => {
            expect(err).to.not.exist;
            expect(data.length).to.equal(360);
            done();
        });
    });

    it('should rebuild using stream', function (done) {
        let message = `Content-Type: text/plain
Content-Transfer-Encoding: base64
X-Attachment-Stream-Size: 264
X-Attachment-Stream-Url: <http://localhost:${HTTP_PORT}/>

`;
        let parsed = indexer.parseMimeTree(message);
        indexer.bodyQuery(parsed, '', (err, data) => {
            expect(err).to.not.exist;
            expect(data.length).to.equal(423);
            indexer.bodyQuery(parsed, {
                path: '1',
                type: ''
            }, (err, data) => {
                expect(err).to.not.exist;
                expect(data.length).to.equal(360);
                done();
            });
        });
    });

    it('should rebuild using stream with truncated content', function (done) {
        let message = `Content-Type: text/plain
Content-Transfer-Encoding: base64
X-Attachment-Stream-Size: 150
X-Attachment-Stream-Url: <http://localhost:${HTTP_PORT}/>

`;
        let parsed = indexer.parseMimeTree(message);
        indexer.bodyQuery(parsed, '', (err, data) => {
            expect(err).to.not.exist;
            expect(data.length).to.equal(267);
            indexer.bodyQuery(parsed, {
                path: '1',
                type: ''
            }, (err, data) => {
                expect(err).to.not.exist;
                expect(data.length).to.equal(204);
                done();
            });
        });
    });

    it('should rebuild using stream with padded content', function (done) {
        let message = `Content-Type: text/plain
Content-Transfer-Encoding: base64
X-Attachment-Stream-Size: 280
X-Attachment-Stream-Url: <http://localhost:${HTTP_PORT}/>

`;
        let parsed = indexer.parseMimeTree(message);
        indexer.bodyQuery(parsed, '', (err, data) => {
            expect(err).to.not.exist;
            expect(data.length).to.equal(447);
            indexer.bodyQuery(parsed, {
                path: '1',
                type: ''
            }, (err, data) => {
                expect(err).to.not.exist;
                expect(data.length).to.equal(384);
                done();
            });
        });
    });

    it('should return correct attachment size in bodystructure', function () {
        let message = `Content-Type: multipart/mixed;
 boundary="foo"

--foo
Content-Type: text/plain
Content-Transfer-Encoding: 7bit

Hello world!
--foo
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=normal.bin
Content-Transfer-Encoding: 7bit

12345678901234567890
--foo
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=stream.bin
Content-Transfer-Encoding: base64
X-Attachment-Stream-Size: 264
X-Attachment-Stream-Url: <http://localhost:${HTTP_PORT}/>

--foo--
`;
        let parsed = indexer.parseMimeTree(message);
        let bodystruct = indexer.getBodyStructure(parsed);
        expect(bodystruct[1][6]).to.equal(20);
        expect(bodystruct[2][6]).to.equal(360);
    });

    it('should rebuild using encoded stream', function (done) {
        let message = `Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable
X-Attachment-Stream-Size: 407
X-Attachment-Stream-Url: <http://localhost:${HTTP_PORT}/qp>
X-Attachment-Stream-Lines: 6
X-Attachment-Stream-Encoded: Yes

`;
        let parsed = indexer.parseMimeTree(message);
        indexer.bodyQuery(parsed, '', (err, data) => {
            expect(err).to.not.exist;
            expect(data.length).to.equal(494);
            indexer.bodyQuery(parsed, {
                path: '1',
                type: ''
            }, (err, data) => {
                expect(err).to.not.exist;
                expect(data.length).to.equal(407);
                done();
            });
        });
    });
});
*/
