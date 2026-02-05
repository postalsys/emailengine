'use strict';

const crypto = require('crypto');
const { Transform } = require('stream');

const MAGIC = Buffer.from('EE01');
const VERSION = 1;
const CHUNK_SIZE = 64 * 1024;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 16;
const HEADER_SIZE = MAGIC.length + 4 + 4 + SALT_LENGTH;

function deriveKey(password, salt) {
    return crypto.scryptSync(password, salt, 32);
}

class EncryptStream extends Transform {
    constructor(secret) {
        super();
        this.secret = secret;
        this.salt = crypto.randomBytes(SALT_LENGTH);
        this.key = deriveKey(secret, this.salt);
        this.buffer = Buffer.alloc(0);
        this.headerWritten = false;
    }

    _writeHeader() {
        if (this.headerWritten) return;

        const versionBuf = Buffer.alloc(4);
        versionBuf.writeUInt32LE(VERSION);

        const chunkSizeBuf = Buffer.alloc(4);
        chunkSizeBuf.writeUInt32LE(CHUNK_SIZE);

        this.push(Buffer.concat([MAGIC, versionBuf, chunkSizeBuf, this.salt]));
        this.headerWritten = true;
    }

    _encryptChunk(chunk) {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv, { authTagLength: AUTH_TAG_LENGTH });

        const encrypted = Buffer.concat([cipher.update(chunk), cipher.final()]);
        const authTag = cipher.getAuthTag();

        const chunkHeader = Buffer.alloc(IV_LENGTH + 4);
        iv.copy(chunkHeader, 0);
        chunkHeader.writeUInt32LE(encrypted.length, IV_LENGTH);

        return Buffer.concat([chunkHeader, encrypted, authTag]);
    }

    _transform(data, encoding, callback) {
        try {
            this._writeHeader();

            this.buffer = Buffer.concat([this.buffer, data]);

            while (this.buffer.length >= CHUNK_SIZE) {
                const chunk = this.buffer.subarray(0, CHUNK_SIZE);
                this.buffer = this.buffer.subarray(CHUNK_SIZE);
                this.push(this._encryptChunk(chunk));
            }

            callback();
        } catch (err) {
            callback(err);
        }
    }

    _flush(callback) {
        try {
            this._writeHeader();

            if (this.buffer.length > 0) {
                this.push(this._encryptChunk(this.buffer));
            }

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
        if (version !== VERSION) {
            throw new Error(`Unsupported encryption version: ${version}`);
        }
        offset += 4;

        this.chunkSize = this.buffer.readUInt32LE(offset);
        offset += 4;

        const salt = this.buffer.subarray(offset, offset + SALT_LENGTH);
        this.key = deriveKey(this.secret, salt);

        this.buffer = this.buffer.subarray(HEADER_SIZE);
        this.headerParsed = true;

        return true;
    }

    _decryptChunk() {
        const minChunkHeader = IV_LENGTH + 4;
        if (this.buffer.length < minChunkHeader) {
            return null;
        }

        const iv = this.buffer.subarray(0, IV_LENGTH);
        const encryptedLength = this.buffer.readUInt32LE(IV_LENGTH);
        if (encryptedLength > CHUNK_SIZE + 256) {
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

        let decrypted;
        try {
            decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
        } catch (err) {
            if (err.message.includes('auth')) {
                throw new Error('Decryption failed: invalid secret or corrupted data');
            }
            throw err;
        }

        this.buffer = this.buffer.subarray(totalChunkSize);

        return decrypted;
    }

    _transform(data, encoding, callback) {
        try {
            this.buffer = Buffer.concat([this.buffer, data]);

            if (!this.headerParsed) {
                if (!this._parseHeader()) {
                    callback();
                    return;
                }
            }

            let decrypted;
            while ((decrypted = this._decryptChunk()) !== null) {
                this.push(decrypted);
            }

            callback();
        } catch (err) {
            callback(err);
        }
    }

    _flush(callback) {
        try {
            if (this.buffer.length > 0) {
                if (!this.headerParsed) {
                    throw new Error('Invalid encrypted file: incomplete header');
                }

                const decrypted = this._decryptChunk();
                if (decrypted !== null) {
                    this.push(decrypted);
                }

                if (this.buffer.length > 0) {
                    throw new Error('Invalid encrypted file: incomplete final chunk');
                }
            }

            callback();
        } catch (err) {
            callback(err);
        }
    }
}

function createEncryptStream(secret) {
    if (!secret) {
        throw new Error('Encryption secret is required');
    }
    return new EncryptStream(secret);
}

function createDecryptStream(secret) {
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
