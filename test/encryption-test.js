'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { encrypt, decrypt, parseEncryptedData } = require('../lib/encrypt');

test('Encryption tests', async t => {
    const testSecret = 'test-secret-password-123';

    await t.test('encrypt() and decrypt() round-trip with string input', async () => {
        const cleartext = 'Hello, World!';
        const encrypted = encrypt(cleartext, testSecret);
        const decrypted = decrypt(encrypted, testSecret);

        assert.strictEqual(decrypted, cleartext);
    });

    await t.test('encrypt() and decrypt() round-trip with unicode content', async () => {
        const cleartext = 'Unicode test: cafe, nino, Munchen';
        const encrypted = encrypt(cleartext, testSecret);
        const decrypted = decrypt(encrypted, testSecret);

        assert.strictEqual(decrypted, cleartext);
    });

    await t.test('encrypt() and decrypt() round-trip with JSON data', async () => {
        const data = { username: 'test', password: 'secret123', nested: { key: 'value' } };
        const cleartext = JSON.stringify(data);
        const encrypted = encrypt(cleartext, testSecret);
        const decrypted = decrypt(encrypted, testSecret);

        assert.deepStrictEqual(JSON.parse(decrypted), data);
    });

    await t.test('encrypt() and decrypt() round-trip with empty string', async () => {
        const cleartext = '';
        const encrypted = encrypt(cleartext, testSecret);
        // Empty string returns as-is (no encryption)
        assert.strictEqual(encrypted, '');
        const decrypted = decrypt(encrypted, testSecret);
        assert.strictEqual(decrypted, '');
    });

    await t.test('encrypt() returns different ciphertext for same input (random IV)', async () => {
        const cleartext = 'Same input text';
        const encrypted1 = encrypt(cleartext, testSecret);
        const encrypted2 = encrypt(cleartext, testSecret);

        // Both should decrypt to same value
        assert.strictEqual(decrypt(encrypted1, testSecret), cleartext);
        assert.strictEqual(decrypt(encrypted2, testSecret), cleartext);

        // But encrypted values should be different due to random IV/salt
        assert.notStrictEqual(encrypted1, encrypted2);
    });

    await t.test('different secrets produce different ciphertext', async () => {
        const cleartext = 'Test data';
        const encrypted1 = encrypt(cleartext, 'secret1');
        const encrypted2 = encrypt(cleartext, 'secret2');

        assert.notStrictEqual(encrypted1, encrypted2);
    });

    await t.test('decrypt() fails with wrong password', async () => {
        const cleartext = 'Sensitive data';
        const encrypted = encrypt(cleartext, 'correct-password');

        assert.throws(
            () => decrypt(encrypted, 'wrong-password'),
            err => {
                assert.ok(err.message.includes('Failed to decrypt'));
                assert.strictEqual(err.code, 'InternalConfigError');
                return true;
            }
        );
    });

    await t.test('decrypt() fails with tampered ciphertext', async () => {
        const cleartext = 'Original data';
        const encrypted = encrypt(cleartext, testSecret);

        // Tamper with the encrypted text portion (last part after $)
        const parts = encrypted.split('$');
        const tamperedHex = parts[6];
        // Flip some bits in the middle
        const tamperedPart =
            tamperedHex.substring(0, 10) +
            (parseInt(tamperedHex[10], 16) ^ 0xf).toString(16) +
            tamperedHex.substring(11);
        parts[6] = tamperedPart;
        const tampered = parts.join('$');

        assert.throws(
            () => decrypt(tampered, testSecret),
            err => {
                assert.ok(err.message.includes('Failed to decrypt'));
                return true;
            }
        );
    });

    await t.test('decrypt() fails with tampered auth tag', async () => {
        const cleartext = 'Protected data';
        const encrypted = encrypt(cleartext, testSecret);

        // Tamper with auth tag (4th part after $)
        const parts = encrypted.split('$');
        const authTag = parts[3];
        const tamperedAuthTag =
            authTag.substring(0, 5) + (parseInt(authTag[5], 16) ^ 0xf).toString(16) + authTag.substring(6);
        parts[3] = tamperedAuthTag;
        const tampered = parts.join('$');

        assert.throws(
            () => decrypt(tampered, testSecret),
            err => {
                assert.ok(err.message.includes('Failed to decrypt'));
                return true;
            }
        );
    });

    await t.test('decrypt() handles cleartext (no encryption marker)', async () => {
        const cleartext = 'Plain text without encryption';
        const decrypted = decrypt(cleartext, testSecret);

        assert.strictEqual(decrypted, cleartext);
    });

    await t.test('decrypt() handles cleartext when no secret provided', async () => {
        const encrypted = encrypt('data', testSecret);
        // With no secret, should return raw string
        const result = decrypt(encrypted, null);
        assert.strictEqual(result, encrypted);
    });

    await t.test('encrypt() returns cleartext when no secret provided', async () => {
        const cleartext = 'unencrypted data';
        const result = encrypt(cleartext, null);
        assert.strictEqual(result, cleartext);
    });

    await t.test('encrypted format has correct structure', async () => {
        const cleartext = 'Test data';
        const encrypted = encrypt(cleartext, testSecret);

        // Format: $format$cipher$authTag$iv$salt$encryptedText
        const parts = encrypted.split('$');
        assert.strictEqual(parts.length, 7);
        assert.strictEqual(parts[0], ''); // Leading $
        assert.strictEqual(parts[1], 'wd01'); // Format version
        assert.strictEqual(parts[2], 'aes-256-gcm'); // Cipher
        assert.strictEqual(parts[3].length, 32); // Auth tag (16 bytes = 32 hex)
        assert.strictEqual(parts[4].length, 24); // IV (12 bytes = 24 hex)
        assert.strictEqual(parts[5].length, 32); // Salt (16 bytes = 32 hex)
        assert.ok(parts[6].length > 0); // Encrypted text
    });

    await t.test('parseEncryptedData() parses valid encrypted string', async () => {
        const cleartext = 'Test';
        const encrypted = encrypt(cleartext, testSecret);
        const parsed = parseEncryptedData(encrypted);

        assert.strictEqual(parsed.format, 'wd01');
        assert.strictEqual(parsed.cipher, 'aes-256-gcm');
        assert.ok(Buffer.isBuffer(parsed.authTag));
        assert.strictEqual(parsed.authTag.length, 16);
        assert.ok(Buffer.isBuffer(parsed.iv));
        assert.strictEqual(parsed.iv.length, 12);
        assert.ok(Buffer.isBuffer(parsed.salt));
        assert.strictEqual(parsed.salt.length, 16);
        assert.ok(Buffer.isBuffer(parsed.data));
    });

    await t.test('parseEncryptedData() returns cleartext format for plain strings', async () => {
        const parsed = parseEncryptedData('plain text');
        assert.strictEqual(parsed.format, 'cleartext');
        assert.strictEqual(parsed.data, 'plain text');
    });

    await t.test('parseEncryptedData() returns cleartext for malformed encrypted string', async () => {
        // Missing parts
        const parsed = parseEncryptedData('$wd01$aes-256-gcm$incomplete');
        assert.strictEqual(parsed.format, 'cleartext');
    });

    await t.test('parseEncryptedData() handles empty input', async () => {
        const parsed = parseEncryptedData('');
        assert.strictEqual(parsed.format, 'cleartext');
        assert.strictEqual(parsed.data, '');
    });

    await t.test('parseEncryptedData() handles null input', async () => {
        const parsed = parseEncryptedData(null);
        assert.strictEqual(parsed.format, 'cleartext');
        assert.strictEqual(parsed.data, '');
    });

    await t.test('scrypt key derivation is consistent for same password and salt', async () => {
        const password = 'test-password';
        const salt = crypto.randomBytes(16);

        // Derive key twice with same inputs
        const key1 = crypto.scryptSync(password, salt, 32);
        const key2 = crypto.scryptSync(password, salt, 32);

        assert.ok(key1.equals(key2));
    });

    await t.test('encrypt/decrypt handles large data', async () => {
        const largeData = 'x'.repeat(100000); // 100KB of data
        const encrypted = encrypt(largeData, testSecret);
        const decrypted = decrypt(encrypted, testSecret);

        assert.strictEqual(decrypted, largeData);
    });

    await t.test('encrypt/decrypt handles special characters', async () => {
        const specialChars = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~\n\t\r';
        const encrypted = encrypt(specialChars, testSecret);
        const decrypted = decrypt(encrypted, testSecret);

        assert.strictEqual(decrypted, specialChars);
    });

    await t.test('decrypt() rejects invalid auth tag length', async () => {
        // Manually construct invalid encrypted data with wrong auth tag length
        const encrypted = encrypt('test', testSecret);
        const parts = encrypted.split('$');
        parts[3] = 'ab'; // Too short auth tag (should be 32 hex chars)
        const invalid = parts.join('$');

        assert.throws(
            () => decrypt(invalid, testSecret),
            err => {
                assert.ok(err.message.includes('Failed to decrypt'));
                return true;
            }
        );
    });

    await t.test('decrypt() rejects invalid IV length', async () => {
        const encrypted = encrypt('test', testSecret);
        const parts = encrypted.split('$');
        parts[4] = 'ab'; // Too short IV (should be 24 hex chars)
        const invalid = parts.join('$');

        assert.throws(
            () => decrypt(invalid, testSecret),
            err => {
                assert.ok(err.message.includes('Failed to decrypt'));
                return true;
            }
        );
    });

    await t.test('decrypt() rejects invalid salt length', async () => {
        const encrypted = encrypt('test', testSecret);
        const parts = encrypted.split('$');
        parts[5] = 'ab'; // Too short salt (should be 32 hex chars)
        const invalid = parts.join('$');

        assert.throws(
            () => decrypt(invalid, testSecret),
            err => {
                assert.ok(err.message.includes('Failed to decrypt'));
                return true;
            }
        );
    });
});
