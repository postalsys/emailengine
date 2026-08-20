'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it): depth-first visitor over a
// plain JSON tree, reporting a JSON-pointer-ish path for assertion messages. Shared by the MCP
// schema suites, which both scan generated JSON Schema for keywords that must not appear.

function walkJson(node, visit, pointer = '') {
    visit(node, pointer);
    if (Array.isArray(node)) {
        node.forEach((entry, i) => walkJson(entry, visit, `${pointer}/${i}`));
    } else if (node && typeof node === 'object') {
        for (const [key, value] of Object.entries(node)) {
            walkJson(value, visit, `${pointer}/${key}`);
        }
    }
}

module.exports = { walkJson };
