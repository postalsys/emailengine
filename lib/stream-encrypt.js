'use strict';

const crypto = require('crypto');
const { Transform } = require('stream');
const { promisify } = require('util');
const { PBKDF2_ITERATIONS, PBKDF2_DIGEST } = require('./encrypt');

const MAGIC = Buffer.from('EE01');
// How the key is derived, by header version. Version 1 used scrypt, which an OpenSSL FIPS provider
// does not offer; versions 2 and 3 use PBKDF2-HMAC-SHA256 with the parameters of the field
// encryption's wd02 scheme.
//
// Versions 1 and 2 seal every chunk on its own, so a file could have its chunks reordered,
// duplicated or dropped, or be cut at a chunk boundary, and still decrypt. Version 3, the one
// written, follows the STREAM construction: each chunk carries a flags byte, and its additional
// authenticated data is the file header, the chunk's index and those flags, so a chunk only
// decrypts at its own position in its own file, and a file that ends without the chunk flagged
// final is refused. Files of the earlier versions still decrypt.
const VERSION = 3;
const PBKDF2 = (password, salt, callback) => crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, 32, PBKDF2_DIGEST, callback);
const KDF = {
    1: (password, salt, callback) => crypto.scrypt(password, salt, 32, callback),
    2: PBKDF2,
    3: PBKDF2
};
const CHUNK_SIZE = 64 * 1024;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 16;
const HEADER_SIZE = MAGIC.length + 4 + 4 + SALT_LENGTH;
const MAX_CHUNK_SIZE = CHUNK_SIZE * 4;
const FLAG_FINAL = 0x01;

// Chunk header: the IV and the ciphertext length, and in version 3 the flags byte after them
const LEGACY_CHUNK_HEADER_SIZE = IV_LENGTH + 4;
const BOUND_CHUNK_HEADER_SIZE = LEGACY_CHUNK_HEADER_SIZE + 1;

// What a version 3 chunk is bound to: the file header, its index and its flags
function chunkAad(header, index, flags) {
    const position = Buffer.alloc(9);
    position.writeBigUInt64BE(BigInt(index), 0);
    position.writeUInt8(flags, 8);
    return Buffer.concat([header, position]);
}

class EncryptStream extends Transform {
    constructor({ key, salt }) {
        super();
        this.key = key;
        this.salt = salt;
        this.buffer = Buffer.alloc(0);
        this.header = null;
        this.chunkIndex = 0;
    }

    _writeHeader() {
        if (this.header) return;

        const versionBuf = Buffer.alloc(4);
        versionBuf.writeUInt32LE(VERSION);

        const chunkSizeBuf = Buffer.alloc(4);
        chunkSizeBuf.writeUInt32LE(CHUNK_SIZE);

        this.header = Buffer.concat([MAGIC, versionBuf, chunkSizeBuf, this.salt]);
        this.push(this.header);
    }

    _encryptChunk(chunk, flags) {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv, { authTagLength: AUTH_TAG_LENGTH });
        cipher.setAAD(chunkAad(this.header, this.chunkIndex++, flags));

        const encrypted = Buffer.concat([cipher.update(chunk), cipher.final()]);
        const authTag = cipher.getAuthTag();

        const chunkHeader = Buffer.alloc(BOUND_CHUNK_HEADER_SIZE);
        iv.copy(chunkHeader, 0);
        chunkHeader.writeUInt32LE(encrypted.length, IV_LENGTH);
        chunkHeader.writeUInt8(flags, IV_LENGTH + 4);

        return Buffer.concat([chunkHeader, encrypted, authTag]);
    }

    _transform(data, encoding, callback) {
        try {
            this._writeHeader();

            this.buffer = Buffer.concat([this.buffer, data]);

            // A full chunk is only sealed once more data follows it: the last chunk is flagged
            // final, and until the stream ends any full chunk could be the last one
            while (this.buffer.length > CHUNK_SIZE) {
                const chunk = this.buffer.subarray(0, CHUNK_SIZE);
                this.buffer = this.buffer.subarray(CHUNK_SIZE);
                this.push(this._encryptChunk(chunk, 0));
            }

            callback();
        } catch (err) {
            callback(err);
        }
    }

    _flush(callback) {
        try {
            this._writeHeader();

            // Always written, even empty, so that a file cut right after a chunk boundary (or
            // right after the header) is told apart from a complete one
            this.push(this._encryptChunk(this.buffer, FLAG_FINAL));
            this.buffer = Buffer.alloc(0);

            this.key = null;
            callback();
        } catch (err) {
            callback(err);
        }
    }
}

class DecryptStream extends Transform {
    constructor(secret) {
        super();
        this.secret = secret;
        this.buffer = Buffer.alloc(0);
        this.headerParsed = false;
        this.key = null;
        this.chunkSize = CHUNK_SIZE;
        this.chunkIndex = 0;
        this.finalSeen = false;
    }

    _parseHeader() {
        if (this.buffer.length < HEADER_SIZE) {
            return false;
        }

        let offset = 0;

        const magic = this.buffer.subarray(offset, offset + MAGIC.length);
        if (!magic.equals(MAGIC)) {
            throw new Error('Invalid encrypted file format: bad magic bytes');
        }
        offset += MAGIC.length;

        const version = this.buffer.readUInt32LE(offset);
        if (!KDF[version]) {
            throw new Error(`Unsupported encryption version: ${version}`);
        }
        this.version = version;
        // Version 3 chunks carry a flags byte and are bound to their position (see VERSION)
        this.boundChunks = version >= 3;
        offset += 4;

        this.chunkSize = this.buffer.readUInt32LE(offset);
        if (this.chunkSize > MAX_CHUNK_SIZE) {
            throw new Error('Invalid chunk size in header');
        }
        offset += 4;

        this.salt = this.buffer.subarray(offset, offset + SALT_LENGTH);
        this.header = Buffer.from(this.buffer.subarray(0, HEADER_SIZE));

        this.buffer = this.buffer.subarray(HEADER_SIZE);
        this.headerParsed = true;

        return true;
    }

    _decryptChunk() {
        const minChunkHeader = this.boundChunks ? BOUND_CHUNK_HEADER_SIZE : LEGACY_CHUNK_HEADER_SIZE;
        if (this.buffer.length < minChunkHeader) {
            return null;
        }

        if (this.finalSeen) {
            throw new Error('Invalid encrypted file: data after the final chunk');
        }

        const iv = this.buffer.subarray(0, IV_LENGTH);
        const encryptedLength = this.buffer.readUInt32LE(IV_LENGTH);
        if (encryptedLength > this.chunkSize + 256) {
            throw new Error('Invalid encrypted chunk length');
        }
        const totalChunkSize = minChunkHeader + encryptedLength + AUTH_TAG_LENGTH;

        if (this.buffer.length < totalChunkSize) {
            return null;
        }

        const encryptedData = this.buffer.subarray(minChunkHeader, minChunkHeader + encryptedLength);
        const authTag = this.buffer.subarray(minChunkHeader + encryptedLength, totalChunkSize);

        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv, { authTagLength: AUTH_TAG_LENGTH });
        decipher.setAuthTag(authTag);

        let flags = 0;
        if (this.boundChunks) {
            flags = this.buffer.readUInt8(IV_LENGTH + 4);
            decipher.setAAD(chunkAad(this.header, this.chunkIndex, flags));
        }

        let decrypted;
        try {
            decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
        } catch (err) {
            if (err.message.includes('auth')) {
                throw new Error('Decryption failed: invalid secret or corrupted data', { cause: err });
            }
            throw err;
        }

        this.buffer = this.buffer.subarray(totalChunkSize);
        this.chunkIndex++;
        if (flags & FLAG_FINAL) {
            this.finalSeen = true;
        }

        return decrypted;
    }

    _processBuffer(callback) {
        try {
            let decrypted;
            while ((decrypted = this._decryptChunk()) !== null) {
                this.push(decrypted);
            }
            callback();
        } catch (err) {
            callback(err);
        }
    }

    _transform(data, encoding, callback) {
        this.buffer = Buffer.concat([this.buffer, data]);

        if (!this.headerParsed) {
            try {
                if (!this._parseHeader()) {
                    callback();
                    return;
                }
            } catch (err) {
                callback(err);
                return;
            }
            KDF[this.version](this.secret, this.salt, (err, key) => {
                if (err) {
                    callback(err);
                    return;
                }
                this.key = key;
                this.secret = null;
                this._processBuffer(callback);
            });
            return;
        }

        this._processBuffer(callback);
    }

    _flush(callback) {
        try {
            if (!this.headerParsed) {
                throw new Error('Invalid encrypted file: incomplete header');
            }

            if (this.buffer.length > 0) {
                const decrypted = this._decryptChunk();
                if (decrypted !== null) {
                    this.push(decrypted);
                }

                if (this.buffer.length > 0) {
                    throw new Error('Invalid encrypted file: incomplete final chunk');
                }
            }

            if (this.boundChunks && !this.finalSeen) {
                throw new Error('Invalid encrypted file: truncated, the final chunk is missing');
            }

            this.key = null;
            callback();
        } catch (err) {
            callback(err);
        }
    }
}

async function createEncryptStream(secret) {
    if (!secret) {
        throw new Error('Encryption secret is required');
    }
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = await promisify(KDF[VERSION])(secret, salt);
    return new EncryptStream({ key, salt });
}

async function createDecryptStream(secret) {
    if (!secret) {
        throw new Error('Decryption secret is required');
    }
    return new DecryptStream(secret);
}

module.exports = {
    createEncryptStream,
    createDecryptStream,
    MAGIC,
    VERSION,
    CHUNK_SIZE,
    HEADER_SIZE
};
