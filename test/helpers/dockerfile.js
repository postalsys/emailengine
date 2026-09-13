'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it).
//
// Shared by the tests that assert things about the Dockerfile. It exists because the COPY grammar is
// worth parsing once: a too-narrow regex previously caused false failures on legitimate refactors (a
// second flag, or a consolidated multi-source COPY), and there is now more than one test that needs
// to know what a COPY line copies.

const fs = require('fs');
const pathlib = require('path');

const DOCKERFILE_PATH = pathlib.join(__dirname, '..', '..', 'Dockerfile');

function readDockerfile() {
    return fs.readFileSync(DOCKERFILE_PATH, 'utf8');
}

/**
 * Source paths of every COPY in the Dockerfile. Handles the real grammar rather than a single
 * (source) capture: any number of `--flag[=value]` options and multiple sources, where the last
 * token is the destination.
 *
 * @param {string} dockerfileText - Contents of the Dockerfile
 * @returns {Set<string>} Every path named as a COPY source
 */
function copiedSources(dockerfileText) {
    let sources = new Set();
    for (let match of dockerfileText.matchAll(/^COPY\s+(.+)$/gm)) {
        // Drop --flag tokens, then every remaining token except the last (the destination) is a source.
        let tokens = match[1]
            .trim()
            .split(/\s+/)
            .filter(token => !token.startsWith('--'));
        for (let source of tokens.slice(0, -1)) {
            sources.add(source);
        }
    }
    return sources;
}

module.exports = { readDockerfile, copiedSources, DOCKERFILE_PATH };
