'use strict';

const crypto = require('crypto');
const { Transform } = require('stream');

// File format constants
const MAGIC = Buffer.from('EE01');
const VERSION = 1;
const CHUNK_SIZE = 64 * 1024; // 64KB chunks
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 16;
const HEADER_SIZE = MAGIC.length + 4 + 4 + SALT_LENGTH; // magic(4) + version(4) + chunkSize(4) + salt(16)

// Derive encryption key from password using scrypt (same params as lib/encrypt.js)
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

        // Chunk format: [12 bytes IV][4 bytes length][N bytes encrypted data][16 bytes auth tag]
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

            // Encrypt any remaining data
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

        // Verify magic bytes
        const magic = this.buffer.subarray(offset, offset + MAGIC.length);
        if (!magic.equals(MAGIC)) {
            throw new Error('Invalid encrypted file format: bad magic bytes');
        }
        offset += MAGIC.length;

        // Read version
        const version = this.buffer.readUInt32LE(offset);
        if (version !== VERSION) {
            throw new Error(`Unsupported encryption version: ${version}`);
        }
        offset += 4;

        // Read chunk size
        this.chunkSize = this.buffer.readUInt32LE(offset);
        offset += 4;

        // Read salt and derive key
        const salt = this.buffer.subarray(offset, offset + SALT_LENGTH);
        this.key = deriveKey(this.secret, salt);

        // Remove header from buffer
        this.buffer = this.buffer.subarray(HEADER_SIZE);
        this.headerParsed = true;

        return true;
    }

    _decryptChunk() {
        // Minimum chunk: IV(12) + length(4) + data(1) + authTag(16) = 33 bytes
        const minChunkHeader = IV_LENGTH + 4;
        if (this.buffer.length < minChunkHeader) {
            return null;
        }

        // Read IV and encrypted data length
        const iv = this.buffer.subarray(0, IV_LENGTH);
        const encryptedLength = this.buffer.readUInt32LE(IV_LENGTH);

        // Calculate total chunk size
        const totalChunkSize = minChunkHeader + encryptedLength + AUTH_TAG_LENGTH;

        if (this.buffer.length < totalChunkSize) {
            return null;
        }

        // Extract encrypted data and auth tag
        const encryptedData = this.buffer.subarray(minChunkHeader, minChunkHeader + encryptedLength);
        const authTag = this.buffer.subarray(minChunkHeader + encryptedLength, totalChunkSize);

        // Decrypt
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

        // Remove processed chunk from buffer
        this.buffer = this.buffer.subarray(totalChunkSize);

        return decrypted;
    }

    _transform(data, encoding, callback) {
        try {
            this.buffer = Buffer.concat([this.buffer, data]);

            // Parse header first
            if (!this.headerParsed) {
                if (!this._parseHeader()) {
                    // Need more data for header
                    callback();
                    return;
                }
            }

            // Decrypt chunks
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
            // Process any remaining data
            if (this.buffer.length > 0) {
                if (!this.headerParsed) {
                    throw new Error('Invalid encrypted file: incomplete header');
                }

                const decrypted = this._decryptChunk();
                if (decrypted !== null) {
                    this.push(decrypted);
                }

                // If there's still data in buffer, it's incomplete/corrupted
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
