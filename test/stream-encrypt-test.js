'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const { Readable, PassThrough } = require('stream');
const { pipeline } = require('stream/promises');
const zlib = require('zlib');
const crypto = require('crypto');

const { createEncryptStream, createDecryptStream, MAGIC, VERSION, CHUNK_SIZE, HEADER_SIZE } = require('../lib/stream-encrypt');

// Helper to convert stream to buffer
async function streamToBuffer(stream) {
    const chunks = [];
    for await (const chunk of stream) {
        chunks.push(chunk);
    }
    return Buffer.concat(chunks);
}

// Helper to create a readable stream from buffer
function bufferToStream(buffer) {
    const readable = new Readable();
    readable.push(buffer);
    readable.push(null);
    return readable;
}

test('Stream encryption tests', async t => {
    const testSecret = 'test-secret-password-123';

    await t.test('createEncryptStream() requires a secret', async () => {
        await assert.rejects(
            () => createEncryptStream(null),
            err => {
                assert.ok(err.message.includes('secret is required'));
                return true;
            }
        );

        await assert.rejects(
            () => createEncryptStream(''),
            err => {
                assert.ok(err.message.includes('secret is required'));
                return true;
            }
        );
    });

    await t.test('createDecryptStream() requires a secret', async () => {
        await assert.rejects(
            () => createDecryptStream(null),
            err => {
                assert.ok(err.message.includes('secret is required'));
                return true;
            }
        );

        await assert.rejects(
            () => createDecryptStream(''),
            err => {
                assert.ok(err.message.includes('secret is required'));
                return true;
            }
        );
    });

    await t.test('round-trip encryption/decryption with small data', async () => {
        const originalData = Buffer.from('Hello, World!');

        const encryptStream = await createEncryptStream(testSecret);
        const decryptStream = await createDecryptStream(testSecret);

        const input = bufferToStream(originalData);
        const encrypted = await streamToBuffer(input.pipe(encryptStream));
        const decrypted = await streamToBuffer(bufferToStream(encrypted).pipe(decryptStream));

        assert.deepStrictEqual(decrypted, originalData);
    });

    await t.test('round-trip encryption/decryption with empty data', async () => {
        const originalData = Buffer.alloc(0);

        const encryptStream = await createEncryptStream(testSecret);
        const decryptStream = await createDecryptStream(testSecret);

        const input = bufferToStream(originalData);
        const encrypted = await streamToBuffer(input.pipe(encryptStream));
        const decrypted = await streamToBuffer(bufferToStream(encrypted).pipe(decryptStream));

        assert.deepStrictEqual(decrypted, originalData);
    });

    await t.test('round-trip encryption/decryption with exactly one chunk', async () => {
        const originalData = crypto.randomBytes(CHUNK_SIZE);

        const encryptStream = await createEncryptStream(testSecret);
        const decryptStream = await createDecryptStream(testSecret);

        const input = bufferToStream(originalData);
        const encrypted = await streamToBuffer(input.pipe(encryptStream));
        const decrypted = await streamToBuffer(bufferToStream(encrypted).pipe(decryptStream));

        assert.deepStrictEqual(decrypted, originalData);
    });

    await t.test('round-trip encryption/decryption with multiple chunks', async () => {
        // Create data that spans multiple chunks (3 full chunks + partial)
        const originalData = crypto.randomBytes(CHUNK_SIZE * 3 + 1000);

        const encryptStream = await createEncryptStream(testSecret);
        const decryptStream = await createDecryptStream(testSecret);

        const input = bufferToStream(originalData);
        const encrypted = await streamToBuffer(input.pipe(encryptStream));
        const decrypted = await streamToBuffer(bufferToStream(encrypted).pipe(decryptStream));

        assert.deepStrictEqual(decrypted, originalData);
    });

    await t.test('round-trip encryption/decryption with large data (1MB)', async () => {
        const originalData = crypto.randomBytes(1024 * 1024);

        const encryptStream = await createEncryptStream(testSecret);
        const decryptStream = await createDecryptStream(testSecret);

        const input = bufferToStream(originalData);
        const encrypted = await streamToBuffer(input.pipe(encryptStream));
        const decrypted = await streamToBuffer(bufferToStream(encrypted).pipe(decryptStream));

        assert.deepStrictEqual(decrypted, originalData);
    });

    await t.test('encrypted data has correct header', async () => {
        const originalData = Buffer.from('Test data');

        const encryptStream = await createEncryptStream(testSecret);
        const input = bufferToStream(originalData);
        const encrypted = await streamToBuffer(input.pipe(encryptStream));

        // Check magic bytes
        assert.deepStrictEqual(encrypted.slice(0, 4), MAGIC);

        // Check version
        assert.strictEqual(encrypted.readUInt32LE(4), VERSION);

        // Check chunk size
        assert.strictEqual(encrypted.readUInt32LE(8), CHUNK_SIZE);

        // Check header size
        assert.ok(encrypted.length >= HEADER_SIZE);
    });

    await t.test('different secrets produce different encrypted output', async () => {
        const originalData = Buffer.from('Same input data');

        const encryptStream1 = await createEncryptStream('secret1');
        const encryptStream2 = await createEncryptStream('secret2');

        const encrypted1 = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream1));
        const encrypted2 = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream2));

        // Different secrets should produce different encrypted data (salt is also different)
        assert.notDeepStrictEqual(encrypted1, encrypted2);
    });

    await t.test('same secret produces different encrypted output (random IV/salt)', async () => {
        const originalData = Buffer.from('Same input data');

        const encryptStream1 = await createEncryptStream(testSecret);
        const encryptStream2 = await createEncryptStream(testSecret);

        const encrypted1 = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream1));
        const encrypted2 = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream2));

        // Same secret should still produce different encrypted data due to random salt/IV
        assert.notDeepStrictEqual(encrypted1, encrypted2);

        // But both should decrypt to the same original data
        const decrypted1 = await streamToBuffer(bufferToStream(encrypted1).pipe(await createDecryptStream(testSecret)));
        const decrypted2 = await streamToBuffer(bufferToStream(encrypted2).pipe(await createDecryptStream(testSecret)));

        assert.deepStrictEqual(decrypted1, originalData);
        assert.deepStrictEqual(decrypted2, originalData);
    });

    await t.test('decryption fails with wrong secret', async () => {
        const originalData = Buffer.from('Secret data');

        const encryptStream = await createEncryptStream('correct-password');
        const decryptStream = await createDecryptStream('wrong-password');

        const encrypted = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream));

        await assert.rejects(streamToBuffer(bufferToStream(encrypted).pipe(decryptStream)), err => {
            assert.ok(err.message.includes('Decryption failed') || err.message.includes('invalid'));
            return true;
        });
    });

    await t.test('decryption fails with tampered data', async () => {
        const originalData = Buffer.from('Original data');

        const encryptStream = await createEncryptStream(testSecret);
        const encrypted = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream));

        // Tamper with encrypted data (flip a bit in the middle)
        const tampered = Buffer.from(encrypted);
        const tamperedIndex = HEADER_SIZE + 20; // Somewhere in the first chunk
        if (tamperedIndex < tampered.length) {
            tampered[tamperedIndex] ^= 0xff;
        }

        const decryptStream = await createDecryptStream(testSecret);

        await assert.rejects(streamToBuffer(bufferToStream(tampered).pipe(decryptStream)), err => {
            assert.ok(err.message.includes('Decryption failed') || err.message.includes('invalid') || err.message.includes('corrupted'));
            return true;
        });
    });

    await t.test('decryption fails with tampered header magic', async () => {
        const originalData = Buffer.from('Test data');

        const encryptStream = await createEncryptStream(testSecret);
        const encrypted = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream));

        // Tamper with magic bytes
        const tampered = Buffer.from(encrypted);
        tampered[0] = 0xff;

        const decryptStream = await createDecryptStream(testSecret);

        await assert.rejects(streamToBuffer(bufferToStream(tampered).pipe(decryptStream)), err => {
            assert.ok(err.message.includes('Invalid encrypted file format') || err.message.includes('bad magic'));
            return true;
        });
    });

    await t.test('decryption fails with incomplete header', async () => {
        const incompleteHeader = Buffer.from('EE0'); // Incomplete magic

        const decryptStream = await createDecryptStream(testSecret);

        await assert.rejects(streamToBuffer(bufferToStream(incompleteHeader).pipe(decryptStream)), err => {
            assert.ok(err.message.includes('incomplete') || err.message.includes('Invalid'));
            return true;
        });
    });

    await t.test('decryption fails with truncated chunk', async () => {
        const originalData = Buffer.from('Test data');

        const encryptStream = await createEncryptStream(testSecret);
        const encrypted = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream));

        // Truncate the encrypted data (remove last few bytes)
        const truncated = encrypted.slice(0, encrypted.length - 10);

        const decryptStream = await createDecryptStream(testSecret);

        await assert.rejects(streamToBuffer(bufferToStream(truncated).pipe(decryptStream)), err => {
            assert.ok(err.message.includes('incomplete') || err.message.includes('Decryption failed') || err.message.includes('corrupted'));
            return true;
        });
    });

    await t.test('integration with gzip - compress then encrypt', async () => {
        const originalData = Buffer.from('{"message": "test data", "count": 12345}');

        // Compress then encrypt
        const gzipStream = zlib.createGzip();
        const encryptStream = await createEncryptStream(testSecret);

        const compressed = await streamToBuffer(bufferToStream(originalData).pipe(gzipStream));
        const encrypted = await streamToBuffer(bufferToStream(compressed).pipe(encryptStream));

        // Decrypt then decompress
        const decryptStream = await createDecryptStream(testSecret);
        const gunzipStream = zlib.createGunzip();

        const decrypted = await streamToBuffer(bufferToStream(encrypted).pipe(decryptStream));
        const decompressed = await streamToBuffer(bufferToStream(decrypted).pipe(gunzipStream));

        assert.deepStrictEqual(decompressed, originalData);
    });

    await t.test('integration with gzip using pipeline', async () => {
        const originalData = Buffer.from('Larger test data for pipeline test'.repeat(1000));

        // Create output buffer through pipeline
        const outputChunks = [];
        const output = new PassThrough();
        output.on('data', chunk => outputChunks.push(chunk));

        // Compress -> Encrypt
        await pipeline(bufferToStream(originalData), zlib.createGzip(), await createEncryptStream(testSecret), output);

        const encrypted = Buffer.concat(outputChunks);

        // Decrypt -> Decompress
        const decryptedChunks = [];
        const decryptOutput = new PassThrough();
        decryptOutput.on('data', chunk => decryptedChunks.push(chunk));

        await pipeline(bufferToStream(encrypted), await createDecryptStream(testSecret), zlib.createGunzip(), decryptOutput);

        const decrypted = Buffer.concat(decryptedChunks);

        assert.deepStrictEqual(decrypted, originalData);
    });

    await t.test('handles streaming data in small chunks', async () => {
        const originalData = crypto.randomBytes(CHUNK_SIZE * 2 + 500);

        // Create a stream that emits data in very small chunks
        const smallChunkStream = new Readable({
            read() {
                // Don't push anything here, we'll push manually
            }
        });

        const encryptStream = await createEncryptStream(testSecret);

        // Start piping
        const encryptedPromise = streamToBuffer(smallChunkStream.pipe(encryptStream));

        // Push data in small chunks (100 bytes at a time)
        let offset = 0;
        const chunkSize = 100;
        while (offset < originalData.length) {
            const end = Math.min(offset + chunkSize, originalData.length);
            smallChunkStream.push(originalData.slice(offset, end));
            offset = end;
        }
        smallChunkStream.push(null);

        const encrypted = await encryptedPromise;
        const decrypted = await streamToBuffer(bufferToStream(encrypted).pipe(await createDecryptStream(testSecret)));

        assert.deepStrictEqual(decrypted, originalData);
    });

    await t.test('handles binary data with all byte values', async () => {
        // Create data with all possible byte values
        const originalData = Buffer.alloc(256 * 4);
        for (let i = 0; i < 256; i++) {
            originalData[i * 4] = i;
            originalData[i * 4 + 1] = (i + 64) % 256;
            originalData[i * 4 + 2] = (i + 128) % 256;
            originalData[i * 4 + 3] = (i + 192) % 256;
        }

        const encryptStream = await createEncryptStream(testSecret);
        const decryptStream = await createDecryptStream(testSecret);

        const encrypted = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream));
        const decrypted = await streamToBuffer(bufferToStream(encrypted).pipe(decryptStream));

        assert.deepStrictEqual(decrypted, originalData);
    });

    await t.test('exported constants have expected values', async () => {
        assert.deepStrictEqual(MAGIC, Buffer.from('EE01'));
        assert.strictEqual(VERSION, 3);
        assert.strictEqual(CHUNK_SIZE, 64 * 1024);
        assert.strictEqual(HEADER_SIZE, 4 + 4 + 4 + 16); // magic + version + chunkSize + salt
    });

    await t.test('decryption handles streaming input in chunks', async () => {
        const originalData = crypto.randomBytes(CHUNK_SIZE * 2);

        const encryptStream = await createEncryptStream(testSecret);
        const encrypted = await streamToBuffer(bufferToStream(originalData).pipe(encryptStream));

        // Create a stream that emits encrypted data in small chunks
        const smallChunkStream = new Readable({
            read() {}
        });

        const decryptStream = await createDecryptStream(testSecret);
        const decryptedPromise = streamToBuffer(smallChunkStream.pipe(decryptStream));

        // Push encrypted data in small chunks (50 bytes at a time)
        let offset = 0;
        const chunkSize = 50;
        while (offset < encrypted.length) {
            const end = Math.min(offset + chunkSize, encrypted.length);
            smallChunkStream.push(encrypted.slice(offset, end));
            offset = end;
        }
        smallChunkStream.push(null);

        const decrypted = await decryptedPromise;
        assert.deepStrictEqual(decrypted, originalData);
    });
});

// Versions 2 and 3 derive the key with PBKDF2-HMAC-SHA256; version 1 did so with scrypt, which an
// OpenSSL FIPS provider does not offer. Files of versions 1 and 2, written by earlier releases,
// still decrypt, and the PBKDF2 parameters are pinned through a file built by hand
test('Stream encryption versions', async t => {
    const secret = 'pinned-export-secret';
    const salt = Buffer.from('101112131415161718191a1b1c1d1e1f', 'hex');
    const pbkdf2Key = crypto.pbkdf2Sync(secret, salt, 600000, 32, 'sha256');

    const build = (version, key, cleartext) => {
        const header = Buffer.alloc(HEADER_SIZE);
        MAGIC.copy(header, 0);
        header.writeUInt32LE(version, MAGIC.length);
        header.writeUInt32LE(CHUNK_SIZE, MAGIC.length + 4);
        salt.copy(header, MAGIC.length + 8);

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
        const encrypted = Buffer.concat([cipher.update(cleartext), cipher.final()]);
        const chunkHeader = Buffer.alloc(16);
        iv.copy(chunkHeader, 0);
        chunkHeader.writeUInt32LE(encrypted.length, 12);
        return Buffer.concat([header, chunkHeader, encrypted, cipher.getAuthTag()]);
    };

    const decryptAll = async buffer => (await streamToBuffer(bufferToStream(buffer).pipe(await createDecryptStream(secret)))).toString();

    await t.test('writes version 3', async () => {
        const encrypted = await streamToBuffer(bufferToStream(Buffer.from('hello')).pipe(await createEncryptStream(secret)));
        assert.strictEqual(encrypted.readUInt32LE(MAGIC.length), 3);
    });

    await t.test('a version 1 file still decrypts', async () => {
        assert.strictEqual(await decryptAll(build(1, crypto.scryptSync(secret, salt, 32), 'written by scrypt')), 'written by scrypt');
    });

    await t.test('a version 2 file decrypts with the pinned PBKDF2 parameters', async () => {
        assert.strictEqual(await decryptAll(build(2, pbkdf2Key, 'written by pbkdf2')), 'written by pbkdf2');
    });

    await t.test('an unknown version is refused', async () => {
        // refused at the header, before any key is derived
        await assert.rejects(() => decryptAll(build(4, Buffer.alloc(32), 'x')), /Unsupported encryption version: 4/);
    });
});

// Version 3 binds every chunk to the file header, its index and its final flag, so a file whose
// chunks were moved around, or that was cut short, is refused instead of decrypting to something
// other than what was written
test('Stream encryption chunk binding', async t => {
    const secret = 'chunk-binding-secret';
    // chunk header in version 3: IV, ciphertext length, flags byte
    const CHUNK_HEADER = 12 + 4 + 1;

    const encrypt = async data => streamToBuffer(bufferToStream(data).pipe(await createEncryptStream(secret)));
    const decrypt = async buffer => streamToBuffer(bufferToStream(buffer).pipe(await createDecryptStream(secret)));

    // Splits a version 3 file into its header and its sealed chunks
    const split = file => {
        const chunks = [];
        let offset = HEADER_SIZE;
        while (offset < file.length) {
            const length = CHUNK_HEADER + file.readUInt32LE(offset + 12) + 16;
            chunks.push(file.subarray(offset, offset + length));
            offset += length;
        }
        return { header: file.subarray(0, HEADER_SIZE), chunks };
    };

    const data = crypto.randomBytes(CHUNK_SIZE * 3 + 100);

    await t.test('a file of whole chunks ends with an empty final chunk', async () => {
        const { chunks } = split(await encrypt(crypto.randomBytes(CHUNK_SIZE * 2)));
        assert.strictEqual(chunks.length, 2);
        assert.strictEqual(chunks[1][16], 1, 'the second chunk is flagged final');
        assert.strictEqual(chunks[0][16], 0);
    });

    await t.test('an empty input still has a final chunk', async () => {
        const encrypted = await encrypt(Buffer.alloc(0));
        assert.strictEqual(split(encrypted).chunks.length, 1);
        assert.deepStrictEqual(await decrypt(encrypted), Buffer.alloc(0));
    });

    await t.test('reordered chunks are refused', async () => {
        const { header, chunks } = split(await encrypt(data));
        await assert.rejects(decrypt(Buffer.concat([header, chunks[1], chunks[0], chunks[2], chunks[3]])), /Decryption failed/);
    });

    await t.test('a dropped chunk is refused', async () => {
        const { header, chunks } = split(await encrypt(data));
        await assert.rejects(decrypt(Buffer.concat([header, chunks[0], chunks[2], chunks[3]])), /Decryption failed/);
    });

    await t.test('a duplicated chunk is refused', async () => {
        const { header, chunks } = split(await encrypt(data));
        await assert.rejects(decrypt(Buffer.concat([header, chunks[0], chunks[0], chunks[1], chunks[2], chunks[3]])), /Decryption failed/);
    });

    await t.test('a file cut at a chunk boundary is refused', async () => {
        const { header, chunks } = split(await encrypt(data));
        await assert.rejects(decrypt(Buffer.concat([header, chunks[0], chunks[1]])), /final chunk is missing/);
    });

    await t.test('a header without chunks is refused', async () => {
        const { header } = split(await encrypt(data));
        await assert.rejects(decrypt(header), /final chunk is missing/);
    });

    await t.test('an empty file is refused', async () => {
        await assert.rejects(decrypt(Buffer.alloc(0)), /incomplete header/);
    });

    await t.test('a chunk flagged final early is refused', async () => {
        const { header, chunks } = split(await encrypt(data));
        const forged = Buffer.from(chunks[1]);
        forged[16] = 1;
        await assert.rejects(decrypt(Buffer.concat([header, chunks[0], forged])), /Decryption failed/);
    });

    await t.test('data after the final chunk is refused', async () => {
        const { header, chunks } = split(await encrypt(data));
        await assert.rejects(decrypt(Buffer.concat([header, ...chunks, chunks[3]])), /data after the final chunk/);
    });

    await t.test('a chunk from another file with the same secret is refused', async () => {
        const first = split(await encrypt(data));
        const second = split(await encrypt(data));
        await assert.rejects(decrypt(Buffer.concat([first.header, second.chunks[0], ...first.chunks.slice(1)])), /Decryption failed/);
    });

    await t.test('a changed chunk size in the header is refused', async () => {
        const encrypted = Buffer.from(await encrypt(data));
        encrypted.writeUInt32LE(CHUNK_SIZE * 2, MAGIC.length + 4);
        await assert.rejects(decrypt(encrypted), /Decryption failed/);
    });
});
