'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it).
//
// Recursively lists the files under a directory that carry the given extension, for the
// guardrail tests that scan a whole tree (the view templates, the source files).

const fs = require('fs');
const pathlib = require('path');

/**
 * @param {string} dir - Directory to walk
 * @param {string} ext - File extension including the dot, e.g. `.hbs`
 * @param {string[]} [out] - Accumulator
 * @returns {string[]} Absolute paths
 */
function listFiles(dir, ext, out = []) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = pathlib.join(dir, entry.name);
        if (entry.isDirectory()) {
            listFiles(full, ext, out);
        } else if (entry.name.endsWith(ext)) {
            out.push(full);
        }
    }
    return out;
}

module.exports = { listFiles };
