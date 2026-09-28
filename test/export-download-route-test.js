'use strict';

// Drives the real GET /v1/account/{account}/export/{exportId}/download handler from
// lib/api-routes/export-routes.js against a recording mock server. Export.getFile is stubbed to
// point at a file this test writes, and fs.createReadStream is wrapped so the test can see the
// source stream the handler opened: that is the one holding the file descriptor.

process.env.EENGINE_SECRET = process.env.EENGINE_SECRET || 'export-download-test-secret';

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');
const { Readable } = require('stream');

const { redis } = require('../lib/db');
const { Export } = require('../lib/export');
const getSecret = require('../lib/get-secret');
const { createEncryptStream } = require('../lib/stream-encrypt');
const exportRoutes = require('../lib/api-routes/export-routes');
const { buildMockArgs } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const logger = { warn() {}, error() {}, debug() {}, info() {} };

// What the handler hands to hapi, via a toolkit that records instead of responding
function fakeToolkit() {
    const out = {};
    const response = {
        type() {
            return response;
        },
        header() {
            return response;
        }
    };
    return {
        out,
        h: {
            response(stream) {
                out.stream = stream;
                return response;
            }
        }
    };
}

const waitFor = (emitter, event, ms = 2000) =>
    Promise.race([new Promise(resolve => emitter.once(event, () => resolve(true))), new Promise(resolve => setTimeout(() => resolve(false), ms).unref())]);

test('export download route', async t => {
    const routes = [];
    await exportRoutes(buildMockArgs({ route: cfg => routes.push(cfg) }));
    const route = routes.find(r => r.method === 'GET' && r.path === '/v1/account/{account}/export/{exportId}/download');
    assert.ok(route);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-export-dl-'));
    const plain = crypto.randomBytes(2 * 1024 * 1024);
    const encryptedPath = path.join(dir, 'export.enc');
    await pipeline(Readable.from([plain]), await createEncryptStream(await getSecret()), fs.createWriteStream(encryptedPath));

    const originalGetFile = Export.getFile;
    const originalCreateReadStream = fs.createReadStream;
    let opened = [];

    t.beforeEach(() => {
        opened = [];
        fs.createReadStream = (...args) => {
            const stream = originalCreateReadStream.apply(fs, args);
            opened.push(stream);
            return stream;
        };
    });

    t.afterEach(() => {
        Export.getFile = originalGetFile;
        fs.createReadStream = originalCreateReadStream;
    });

    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

    const request = { params: { account: 'acc', exportId: 'exp_1' }, logger };

    await t.test('an encrypted export decrypts to the original content', async () => {
        Export.getFile = async () => ({ filePath: encryptedPath, isEncrypted: true, filename: 'export.ndjson.gz' });
        const { h, out } = fakeToolkit();
        await route.handler(request, h);

        const chunks = [];
        for await (const chunk of out.stream) {
            chunks.push(chunk);
        }
        assert.ok(Buffer.concat(chunks).equals(plain));
    });

    await t.test('an aborted encrypted download releases the source file', async () => {
        Export.getFile = async () => ({ filePath: encryptedPath, isEncrypted: true, filename: 'export.ndjson.gz' });
        const { h, out } = fakeToolkit();
        await route.handler(request, h);

        assert.equal(opened.length, 1);
        const source = opened[0];
        const sourceClosed = waitFor(source, 'close');

        // Read a little, then do what hapi does when the client disconnects
        await new Promise(resolve => out.stream.once('data', resolve));
        out.stream.destroy();

        assert.equal(await sourceClosed, true, 'the file read stream must close, or its descriptor leaks');
        assert.ok(source.destroyed);
    });

    await t.test('a source read error ends the response instead of leaving it open', async () => {
        // A directory opens fine and fails on the first read (EISDIR), which is the shape of an
        // I/O error part way through a download
        Export.getFile = async () => ({ filePath: dir, isEncrypted: true, filename: 'export.ndjson.gz' });
        const { h, out } = fakeToolkit();
        await route.handler(request, h);

        const errored = waitFor(out.stream, 'error');
        out.stream.resume();
        assert.equal(await errored, true, 'the response stream must fail so hapi ends the response');
    });
});
