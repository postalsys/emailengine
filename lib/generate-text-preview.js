'use strict';

const { compile } = require('html-to-text');

const htmlToText = compile({
    wordwrap: 1000,
    selectors: [
        { selector: 'p', options: { leadingLineBreaks: 1, trailingLineBreaks: 1, format: 'inline' } },
        { selector: 'pre', options: { leadingLineBreaks: 1, trailingLineBreaks: 1, format: 'inline' } },
        //{ selector: 'table.class#id', format: 'skip' },
        { selector: 'a', options: { ignoreHref: true, linkBrackets: false } },
        { selector: 'img', format: 'skip' },
        { selector: 'hr', format: 'skip' },
        { selector: 'blockquote', format: 'inline' },
        { selector: 'td', format: 'inline' },
        { selector: 'tr', format: 'inline' },
        { selector: 'h1', options: { uppercase: false } },
        { selector: 'h2', options: { uppercase: false } },
        { selector: 'h3', options: { uppercase: false } },
        { selector: 'h4', options: { uppercase: false } },
        { selector: 'h5', options: { uppercase: false } },
        { selector: 'h6', options: { uppercase: false } },
        { selector: 'table', options: { uppercaseHeaderCells: false } }
    ],
    hideLinkHrefIfSameAsText: true
});

function generateTextPreview(textContent, maxLength) {
    maxLength = maxLength || 128;
    if (!textContent || (!textContent.plain && !textContent.html)) {
        return null;
    }

    let text;
    if (textContent.html) {
        text = htmlToText(textContent.html);
    } else {
        text = textContent.plain;
    }

    text = text.replace(/\r?\n/g, ' ').replace(/[\s]+/g, ' ').trim();

    if (text.length <= maxLength) {
        return text.replace(/[\u034f\u200c\u00a0]+/g, ' ').trim();
    }

    let truncated = text.substring(0, maxLength);

    // Drop the word the cut landed in, unless the chunk is one unbroken run (a long URL or
    // token), in which case the hard cut is the only preview there is
    let preview = truncated.replace(/([^\s.!?]*)$/, '');
    if (!preview.trim()) {
        preview = truncated;
    }

    return preview.replace(/[\u034f\u200c\u00a0]+/g, ' ').trim();
}

module.exports = { generateTextPreview };

//process.stdout.write(generateTextPreview({ html: require('fs').readFileSync(process.argv[2], 'utf-8') }));
