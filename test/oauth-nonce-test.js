'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { NONCE_BYTES } = require('../lib/consts');

// Regex that validates OAuth state nonces (from workers/api.js security fix)
const NONCE_VALIDATION_REGEX = /^[A-Za-z0-9_-]{21,22}$/;

test('OAuth nonce encoding tests', async t => {
    await t.test('base64url encoded nonce matches validation regex', async () => {
        // Generate multiple nonces to ensure consistent behavior
        for (let i = 0; i < 100; i++) {
            const nonce = crypto.randomBytes(NONCE_BYTES).toString('base64url');
            assert.ok(NONCE_VALIDATION_REGEX.test(nonce), `base64url nonce should match validation regex: ${nonce}`);
        }
    });

    await t.test('standard base64 encoded nonce fails validation regex', async () => {
        // Standard base64 can contain +, /, and = which are not in the validation regex
        let foundInvalidChar = false;
        for (let i = 0; i < 1000 && !foundInvalidChar; i++) {
            const nonce = crypto.randomBytes(NONCE_BYTES).toString('base64');
            if (!NONCE_VALIDATION_REGEX.test(nonce)) {
                foundInvalidChar = true;
            }
        }
        assert.ok(foundInvalidChar, 'standard base64 should eventually produce characters that fail validation (+=/) ');
    });

    await t.test('no NONCE_BYTES usage with plain base64 encoding in codebase', async () => {
        // Static analysis: scan source files for incorrect nonce encoding
        // This prevents regression of the base64 vs base64url bug
        const sourceFiles = ['workers/api.js', 'lib/routes-ui.js', 'lib/ui-routes/account-routes.js', 'lib/api-routes/account-routes.js'];

        const problematicPattern = /NONCE_BYTES\)\.toString\(['"]base64['"]\)/;
        const violations = [];

        for (const file of sourceFiles) {
            const filePath = path.join(__dirname, '..', file);
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf8');
                const lines = content.split('\n');
                lines.forEach((line, index) => {
                    if (problematicPattern.test(line)) {
                        violations.push(`${file}:${index + 1}: ${line.trim()}`);
                    }
                });
            }
        }

        assert.strictEqual(violations.length, 0, `Found NONCE_BYTES with plain base64 encoding (should use base64url):\n${violations.join('\n')}`);
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
});
