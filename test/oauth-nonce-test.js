'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { NONCE_BYTES } = require('../lib/consts');

// Regex that validates OAuth state nonces (from workers/api.js security fix)
// Accepts both base64url and base64 encoding for backward compatibility
const NONCE_VALIDATION_REGEX = /^[A-Za-z0-9_\-+/]{21,22}={0,2}$/;

test('OAuth nonce encoding tests', async t => {
    await t.test('base64url encoded nonce matches validation regex', async () => {
        // Generate multiple nonces to ensure consistent behavior
        for (let i = 0; i < 100; i++) {
            const nonce = crypto.randomBytes(NONCE_BYTES).toString('base64url');
            assert.ok(NONCE_VALIDATION_REGEX.test(nonce), `base64url nonce should match validation regex: ${nonce}`);
        }
    });

    await t.test('standard base64 encoded nonce passes validation regex', async () => {
        // Standard base64 can contain +, /, and = which are now accepted for backward compatibility
        for (let i = 0; i < 100; i++) {
            const nonce = crypto.randomBytes(NONCE_BYTES).toString('base64');
            assert.ok(NONCE_VALIDATION_REGEX.test(nonce), `base64 nonce should match validation regex: ${nonce}`);
        }
    });

    await t.test('new nonce generation uses base64url encoding in codebase', async () => {
        // Static analysis: scan source files for nonce generation
        // New nonces should use base64url, but validation accepts both for backward compatibility
        const sourceFiles = ['workers/api.js', 'lib/routes-ui.js', 'lib/ui-routes/account-routes.js', 'lib/api-routes/account-routes.js'];

        const base64urlPattern = /NONCE_BYTES\)\.toString\(['"]base64url['"]\)/;
        const base64Pattern = /NONCE_BYTES\)\.toString\(['"]base64['"]\)/;
        const usesBase64url = [];
        const usesBase64 = [];

        for (const file of sourceFiles) {
            const filePath = path.join(__dirname, '..', file);
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf8');
                if (base64urlPattern.test(content)) {
                    usesBase64url.push(file);
                }
                if (base64Pattern.test(content)) {
                    usesBase64.push(file);
                }
            }
        }

        // New nonce generation should use base64url (old base64 nonces are only accepted for backward compat)
        assert.strictEqual(usesBase64.length, 0, `Found NONCE_BYTES with plain base64 encoding (new code should use base64url):\n${usesBase64.join('\n')}`);
    });

    await t.test('all NONCE_BYTES usages use base64url encoding', async () => {
        // Verify that all nonce generation uses base64url
        const sourceDir = path.join(__dirname, '..');
        const filesToCheck = [];

        // Collect all JS files in lib/ and workers/
        const collectFiles = dir => {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
                    collectFiles(fullPath);
                } else if (entry.isFile() && entry.name.endsWith('.js')) {
                    filesToCheck.push(fullPath);
                }
            }
        };

        collectFiles(path.join(sourceDir, 'lib'));
        collectFiles(path.join(sourceDir, 'workers'));

        const nonceUsagePattern = /NONCE_BYTES\)\.toString\(['"]base64(?:url)?['"]\)/g;
        const correctPattern = /NONCE_BYTES\)\.toString\(['"]base64url['"]\)/;
        const incorrectUsages = [];

        for (const filePath of filesToCheck) {
            const content = fs.readFileSync(filePath, 'utf8');
            const lines = content.split('\n');
            lines.forEach((line, index) => {
                if (nonceUsagePattern.test(line) && !correctPattern.test(line)) {
                    const relativePath = path.relative(sourceDir, filePath);
                    incorrectUsages.push(`${relativePath}:${index + 1}: ${line.trim()}`);
                }
                // Reset regex lastIndex for next test
                nonceUsagePattern.lastIndex = 0;
            });
        }

        assert.strictEqual(incorrectUsages.length, 0, `Found NONCE_BYTES with incorrect encoding:\n${incorrectUsages.join('\n')}`);
    });

    await t.test('nonce validation accepts both base64 and base64url formats', async () => {
        // Verify that files using data.n validate the format with backward-compatible regex
        const filesToCheck = ['lib/routes-ui.js', 'lib/ui-routes/account-routes.js'];

        // Pattern: validates nonce and throws Boom error for invalid format
        // Now accepts both base64url and base64 encoding
        const validationPattern = /if.*!.*test\(nonce\).*\{[\s\S]*?Boom\.boomify.*Invalid nonce format/;

        const missingValidation = [];

        for (const file of filesToCheck) {
            const filePath = path.join(__dirname, '..', file);
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf8');
                if (!validationPattern.test(content)) {
                    missingValidation.push(`${file}: missing nonce validation with error`);
                }
            }
        }

        assert.strictEqual(missingValidation.length, 0, `Files using data.n must validate and reject invalid nonces:\n${missingValidation.join('\n')}`);
    });

    await t.test('invalid nonces are rejected', async () => {
        // Test that completely invalid nonces are still rejected
        const invalidNonces = [
            '', // empty
            'short', // too short
            'a'.repeat(30), // too long (no padding scenario)
            '!@#$%^&*(){}[]|\\', // invalid characters
            'valid123456789012345===', // too much padding
            'valid12345678901234567890====' // way too long with padding
        ];

        for (const nonce of invalidNonces) {
            assert.ok(!NONCE_VALIDATION_REGEX.test(nonce), `Invalid nonce should be rejected: ${nonce}`);
        }
    });

    await t.test('edge cases for base64/base64url characters', async () => {
        // Test specific edge cases for the character differences
        const base64urlOnlyChars = 'AAAAAAAAAAAAAAAAAAA_-'; // 21 chars with _ and -
        const base64OnlyChars = 'AAAAAAAAAAAAAAAAAAA+/=='; // 21 chars + padding with + and /
        const mixedChars = 'AAAAAAAAAAAAAAAA_-+/'; // mixed characters (20 chars)

        assert.ok(NONCE_VALIDATION_REGEX.test(base64urlOnlyChars), 'base64url-only chars should pass');
        assert.ok(NONCE_VALIDATION_REGEX.test(base64OnlyChars), 'base64-only chars with padding should pass');
        assert.ok(!NONCE_VALIDATION_REGEX.test(mixedChars), 'too short nonce should fail');
    });
});
