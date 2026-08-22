'use strict';

const { analyze } = require('@postalsys/email-content');
const { mimeHtml, textToHtml } = require('@postalsys/email-text-tools');
const { getBoolean, readEnvValue } = require('./tools');
const { COLLAPSE_CLASS, COLLAPSE_TOGGLE_CLASS } = require('./consts');
const logger = require('./logger');

/**
 * Web-safe HTML generation for message bodies.
 *
 * On top of the sanitization mimeHtml() performs, a reply that quotes the whole thread gets a
 * single collapse marker: everything from the point where the sender stopped writing to the end
 * of the body is wrapped in one <details> element.
 *
 * The marker carries structure and class names, and nothing else - no label text, no styling. A
 * renderer that knows about it puts its own label into the <summary> and styles the block; a
 * renderer that strips unknown elements is left with the body it would have got anyway.
 */

const COLLAPSE_OPEN_MARKUP = `<details class="${COLLAPSE_CLASS}"><summary class="${COLLAPSE_TOGGLE_CLASS}"></summary>`;
const COLLAPSE_CLOSE_MARKUP = '</details>';

/**
 * Segment labels that may be folded away.
 *
 * Every segment also carries the extractor's own `visibility`, and folding on that alone was
 * rejected: it marks signatures as collapsible, and a signature sits inside the content block for
 * Gmail-style replies, which moves the cut point somewhere the marker can only fold a fraction of
 * the thread. The label set decides what kind of content may be folded, and `visibility` is still
 * consulted, so a segment the extractor was not confident enough to collapse is never folded here
 * either.
 */
const COLLAPSIBLE_TYPES = new Set(['REPLY_HISTORY', 'FORWARDED_CONTENT', 'DISCLAIMER']);

// A shorter tail is not worth a control: hiding two lines behind a click adds noise instead of
// removing it.
const MIN_COLLAPSE_CHARS = 120;

/**
 * Largest body the extractor is run over.
 *
 * Extraction is synchronous and roughly linear in body size, and two of the callers run on the
 * IMAP worker for every newly seen message, so this is a bound on how long a single message may
 * block that event loop - around 25 ms at this size. Larger bodies are passed through unfolded
 * rather than analysed in part: a cut point derived from a truncated body says nothing about the
 * content past the truncation, which is exactly where new content would have to be looked for.
 */
const MAX_ANALYZE_CHARS = 256 * 1024;

// Opt-out for operators who need the previous output shape, or who do not want to pay for
// extraction on every notified message.
const DISABLE_THREAD_COLLAPSE = getBoolean(readEnvValue('EENGINE_DISABLE_THREAD_COLLAPSE'));

/**
 * Base styles for messages that only have a plain text body.
 *
 * mimeHtml() applies its own copy of these whenever it converts text to HTML itself. Once a
 * collapse marker is involved the conversion happens here instead, so the styling has to travel
 * with it, otherwise a plain text reply would lose its quote colouring the moment it became
 * collapsible. juice inlines the block and the sanitizer then drops the tag.
 *
 * Kept byte for byte identical to INLINE_STYLE_BLOCK in @postalsys/email-text-tools, so the two
 * can be diffed when that package restyles quoted text.
 */
const PLAINTEXT_STYLE_BLOCK = `<style>

body, td, th, p {
    font-family: sans-serif;
    font-size: 12px;
}

blockquote {
    border-left-width: 2px;
    border-left-style: solid;

    border-left-color: darkblue;
    color: darkblue;

    margin: 1rem 0;
    padding-left: 1rem;
}

blockquote blockquote{
    border-left-color: royalblue;
    color: royalblue;
}

blockquote blockquote blockquote{
    border-left-color: dodgerblue;
    color: dodgerblue;
}

blockquote blockquote blockquote blockquote{
    border-left-color: darkblue;
    color: darkblue;
}

</style>`;

// Table internals can not host a wrapper element. A <details> opened between table cells is
// foster-parented out of the table by the HTML parser, which would leave the content behind and
// move an empty control above the table, so such cut points are skipped.
const TABLE_INTERNAL_TAG = /^<(?:table|thead|tbody|tfoot|tr|td|th|col|colgroup|caption)[\s/>]/i;

// Longest tag name the check above can match, plus the angle bracket and the delimiter.
const TABLE_INTERNAL_TAG_MAX = 12;

// The document end tags are within a few bytes of the end of any real body, so only the tail is
// searched for them rather than lowercasing a body that can be a quarter of a megabyte.
const DOCUMENT_END_TAIL = 4096;
const DOCUMENT_END_TAG = /<\/(?:body|html)[\s>]/gi;

/**
 * Formats an address object the way the extractor expects it, as signature evidence.
 *
 * @param {Object} [from] - Address object carrying `name` and/or `address`
 * @returns {string|null} "Name <address>" style string, or null when there is nothing to format
 */
function formatSender(from) {
    if (!from) {
        return null;
    }

    let name = (from.name || '').trim();
    let address = (from.address || '').trim();

    if (name && address) {
        return `${name} <${address}>`;
    }

    return address || name || null;
}

/**
 * Normalizes text the same way the extractor does, so the offsets it reports index this string.
 *
 * Mirrors canonicaliseText() in @postalsys/email-content: BOM removal, LF line endings, NUL
 * removal and NFC normalization. Anything else would shift the offsets.
 *
 * There is no HTML counterpart on purpose. HTML offsets come from source ranges over the string
 * exactly as it was handed to the extractor, so HTML must not be normalized before slicing it.
 *
 * @param {string} text - Decoded plain text body
 * @returns {string} Canonical text
 */
function canonicaliseText(text) {
    let canonical = text;

    if (canonical.charCodeAt(0) === 0xfeff) {
        canonical = canonical.slice(1);
    }

    canonical = canonical.replace(/\r\n?/g, '\n').replace(/\0/g, '');

    try {
        canonical = canonical.normalize('NFC');
    } catch (_err) {
        // Extremely long or malformed input can defeat NFC. Unnormalized text still slices.
    }

    return canonical;
}

/**
 * Finds the offset where the quoted tail of a message starts.
 *
 * Both bodies are handed to the extractor even though only one of them can be spliced. The one it
 * does not pick is what tells it that the other is a stub or failed to parse, and that decision is
 * what the caller reads to know whether folding is safe at all.
 *
 * @param {Object} content - Message content passed to the extractor
 * @returns {Promise<{representation: string, offset: number}|null>} Cut point, or null when the
 *   message has no tail worth folding
 */
async function findCollapseCut(content) {
    let result = await analyze(content);

    let representation = result.primaryRepresentation;
    if (representation !== 'html' && representation !== 'text') {
        return null;
    }

    // Hidden segments are held back from `segments`, so both lists are needed to see the body in
    // document order. Only the representation that drove the classification can be spliced.
    let segments = result.segments
        .concat(result.hiddenSegments)
        .filter(segment => segment.source.kind === 'mime-part' && segment.source.representation === representation)
        .sort((a, b) => a.source.start - b.source.start);

    let cutIndex = segments.length;
    let collapsedChars = 0;
    let seenContent = false;

    while (cutIndex > 0) {
        let segment = segments[cutIndex - 1];
        // `visibility` is the extractor's confidence gate. A quote it left visible is one it was
        // not sure about, and folding it anyway would override the one judgement it publishes.
        if (!COLLAPSIBLE_TYPES.has(segment.type) || segment.visibility === 'show') {
            break;
        }
        collapsedChars += segment.text.trim().length;
        cutIndex--;
    }

    if (!cutIndex || cutIndex === segments.length || collapsedChars < MIN_COLLAPSE_CHARS) {
        // Nothing to fold, nothing left over once it is folded, or a tail too short to be worth a
        // control. Folding a message into nothing but a button is worse than showing it.
        return null;
    }

    for (let index = 0; index < cutIndex && !seenContent; index++) {
        seenContent = !!segments[index].text.trim();
    }

    return seenContent ? { representation, offset: segments[cutIndex].source.start } : null;
}

/**
 * Locates the next element start at or after an offset, stepping over comments.
 *
 * The offset reported by the extractor sits on the boundary between two blocks, which may still
 * have closing tags of the preceding content in front of it. Opening the marker on the next
 * element start keeps it out of the middle of markup.
 *
 * @returns {number} Offset of the element start, or -1 when there is none
 */
function nextElementStart(html, from) {
    let pos = from;

    while (pos < html.length) {
        let next = html.indexOf('<', pos);
        if (next < 0) {
            return -1;
        }

        if (html.startsWith('<!--', next)) {
            let commentEnd = html.indexOf('-->', next + 4);
            if (commentEnd < 0) {
                return -1;
            }
            pos = commentEnd + 3;
            continue;
        }

        if (/^<[a-z]/i.test(html.slice(next, next + 2))) {
            return next;
        }

        pos = next + 1;
    }

    return -1;
}

/**
 * Offset the marker has to be closed at, so it does not wrap the document epilogue.
 *
 * @returns {number} Offset to close at
 */
function collapseCloseOffset(html) {
    let tailStart = Math.max(html.length - DOCUMENT_END_TAIL, 0);
    let tail = html.slice(tailStart);

    DOCUMENT_END_TAG.lastIndex = 0;
    let match = DOCUMENT_END_TAG.exec(tail);

    return match ? tailStart + match.index : html.length;
}

/**
 * Splices the collapse marker into an HTML body.
 *
 * The marker is opened at the cut point and closed at the end of the body. Tags stay balanced
 * because exactly one element is opened and one closed, so an unclosed ancestor between the two
 * ends the marker early - the fold then covers less of the tail than it could, which is a worse
 * fold rather than broken markup.
 *
 * @returns {string|null} HTML carrying the marker, or null when there is no safe place for it
 */
function collapseHtml(html, offset) {
    if (offset <= 0 || offset >= html.length) {
        return null;
    }

    let start = nextElementStart(html, offset);
    if (start < 0 || TABLE_INTERNAL_TAG.test(html.slice(start, start + TABLE_INTERNAL_TAG_MAX))) {
        return null;
    }

    let closeOffset = collapseCloseOffset(html);
    if (closeOffset <= start) {
        return null;
    }

    return html.slice(0, start) + COLLAPSE_OPEN_MARKUP + html.slice(start, closeOffset) + COLLAPSE_CLOSE_MARKUP + html.slice(closeOffset);
}

/**
 * Builds HTML with a collapse marker from a plain text body.
 *
 * Messages without an HTML part are analysed as text - the HTML mimeHtml() would generate from
 * them carries no quote structure the extractor could read, only the structure it inferred from
 * the text in the first place. The two halves are therefore converted separately here.
 *
 * @returns {string|null} Generated HTML, or null when the cut point is out of range
 */
function collapseText(text, offset) {
    if (offset <= 0 || offset >= text.length) {
        return null;
    }

    return PLAINTEXT_STYLE_BLOCK + textToHtml(text.slice(0, offset)) + COLLAPSE_OPEN_MARKUP + textToHtml(text.slice(offset)) + COLLAPSE_CLOSE_MARKUP;
}

/**
 * Folds the quoted thread of a message into a single collapsible block.
 *
 * @param {Object} messageData - Message object
 * @param {Object} messageData.text - Decoded bodies, as `text.html` and `text.plain`
 * @param {string} [messageData.subject] - Subject line
 * @param {Object} [messageData.from] - Sender address
 * @param {string} [messageData.inReplyTo] - In-Reply-To header value
 * @returns {Promise<{html: string}|null>} Replacement content for mimeHtml(), or null when the
 *   message has no tail worth folding
 */
async function collapseThreadHistory(messageData) {
    let bodies = messageData.text || {};
    let html = (bodies.html || '').toString();
    let text = (bodies.plain || '').toString();

    if (html.length + text.length > MAX_ANALYZE_CHARS) {
        return null;
    }

    html = html.trim() ? html : '';
    text = text.trim() ? text : '';

    if (!html && !text) {
        return null;
    }

    let cut = await findCollapseCut({
        html: html || null,
        text: text || null,
        subject: messageData.subject || null,
        from: formatSender(messageData.from),
        inReplyTo: messageData.inReplyTo || null
    });

    if (!cut) {
        return null;
    }

    let collapsed;
    if (cut.representation === 'html') {
        collapsed = collapseHtml(html, cut.offset);
    } else if (html) {
        // The extractor can pick the text representation over an HTML one it could not read - a
        // stub HTML part, or markup that failed to parse. Generating the body from the text there
        // would fold the thread at the cost of throwing the sender's real HTML away, which is a
        // far bigger change than the fold is worth, so those messages are rendered whole.
        return null;
    } else {
        // Text offsets index the extractor's canonical form, so the same normalization has to be
        // applied before slicing. It is done here rather than up front because the HTML path,
        // which is the common one, has no use for it.
        collapsed = collapseText(canonicaliseText(text), cut.offset);
    }

    return collapsed ? { html: collapsed } : null;
}

/**
 * Converts the bodies of a message object into sanitized, web-safe HTML.
 *
 * @param {Object} messageData - Message object, as described on collapseThreadHistory()
 * @returns {Promise<string>} Sanitized HTML
 */
async function messageWebSafeHtml(messageData) {
    let source = { html: messageData.text.html, text: messageData.text.plain };

    if (!DISABLE_THREAD_COLLAPSE) {
        try {
            let collapsed = await collapseThreadHistory(messageData);
            if (collapsed) {
                source = collapsed;
            }
        } catch (err) {
            // A message that can not be folded is still a message. Render all of it.
            logger.warn({ msg: 'Failed to mark quoted thread content', err });
        }
    }

    return mimeHtml(source);
}

/**
 * The web-safe form of a fetched text response.
 *
 * Both MIME parts go in and one rendering comes out: the HTML is generated from whichever parts
 * exist, so the plaintext part beside it would be the same message a second time. A caller that
 * wants the parts as the server stored them simply does not ask for this.
 *
 * A response carrying neither body is handed back untouched - there is nothing to render, and an
 * empty `html` claiming to be web-safe says more than the message does.
 *
 * @param {Object} textData - `{ plain, html, hasMore }` as fetched
 * @returns {Promise<Object>} `{ html, webSafe: true, hasMore }`, or the input when there is no body
 */
async function webSafeTextResponse(textData) {
    if (!textData || (!textData.plain && !textData.html)) {
        return textData;
    }

    return {
        html: await messageWebSafeHtml({ text: { html: textData.html, plain: textData.plain } }),
        webSafe: true,
        hasMore: !!textData.hasMore
    };
}

/**
 * Expands the `webSafeHtml` shorthand into the options it stands for, and settles
 * `embedAttachedImages` either way.
 *
 * One spelling of the expansion, which the message-retrieval paths had three drifting copies of -
 * a shorthand that means different things per provider is not a shorthand. Called at the facade
 * (Account.getMessage) and again inside the Gmail and Graph clients, which are reachable on their
 * own; it is idempotent, so the second call on those paths is a no-op rather than a second policy.
 *
 * `embedAttachedImages` is the one part a caller may keep: inlining every referenced attachment as
 * a data URI is what makes a web-safe body renderable in a browser with no second request, and it
 * is also what multiplies its size, which is the wrong trade for anything that reads the body
 * rather than displays it (the MCP tools, an export, a classifier). An explicit `false` therefore
 * wins over the shorthand and the `cid:` references are left as they are; the sanitizing and the
 * single-rendering promise are unaffected.
 *
 * The tri-state that makes that possible - the query schema deliberately carries no default, so
 * absent stays distinguishable from an explicit false - is resolved to a boolean here rather than
 * left for four backends to each read as truthy or not. Absent means the shorthand decides.
 *
 * @param {Object} options - request options, modified in place
 * @returns {Object} the same options object
 */
function applyWebSafeHtmlOptions(options) {
    if (options.webSafeHtml) {
        options.textType = '*';
        options.preProcessHtml = true;
    }

    options.embedAttachedImages = options.embedAttachedImages === undefined ? !!options.webSafeHtml : !!options.embedAttachedImages;

    return options;
}

module.exports = {
    messageWebSafeHtml,
    webSafeTextResponse,
    applyWebSafeHtmlOptions,
    collapseThreadHistory
};
