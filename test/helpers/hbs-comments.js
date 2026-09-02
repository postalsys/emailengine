'use strict';

// Helper (not named *-test.js, so the Node test runner ignores it).
//
// Blanks Handlebars comments ({{!-- --}} and {{! }}) in a template source for the guardrail
// tests that scan templates: the ui/* partials document their own usage inside comments, with
// example invocations and element names that are not real markup. Newlines are preserved so
// line numbers stay accurate.

function stripHandlebarsComments(source) {
    return source.replace(/\{\{!--[\s\S]*?--\}\}|\{\{![\s\S]*?\}\}/g, comment => comment.replace(/[^\n]/g, ' '));
}

module.exports = { stripHandlebarsComments };
