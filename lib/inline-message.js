'use strict';

const HTMLParser = require('node-html-parser');
const he = require('he');
const { htmlToText } = require('html-to-text');
const beautifyHtml = require('js-beautify').html;
const linkifyIt = require('linkify-it');
const tlds = require('tlds');

const linkify = linkifyIt()
    .tlds(tlds) // Reload with full tlds list
    .tlds('onion', true) // Add unofficial `.onion` domain
    .add('git:', 'http:') // Add `git:` protocol as "alias"
    .set({ fuzzyIP: true });

const MAX_HTML_PARSE_LENGTH = 2 * 1024 * 1024; // do not parse HTML messages larger than 2MB to plaintext

function getHtmlBody(html) {
    html = ((html && html.toString()) || '').trim();
    if (!html) {
        return '';
    }

    const root = HTMLParser.parse(html);
    let body = root.querySelector('body');
    if (!body) {
        body = root.querySelector('html') || root;
    }
    return ((body && body.innerHTML) || '').trim();
}

function formatAddressHtml(addr) {
    if (!addr || (!addr.name && !addr.address)) {
        return false;
    }

    let parts = [];
    if (addr.name) {
        parts.push(he.encode(addr.name, { useNamedReferences: true }));
    }
    if (addr.address) {
        parts.push(
            `${he.encode('<', { useNamedReferences: true })}<a href="mailto:${he.encode(addr.address, { useNamedReferences: true })}" class="">${he.encode(
                addr.address,
                { useNamedReferences: true }
            )}</a>${he.encode('>', { useNamedReferences: true })}`
        );
    }

    return parts.join(' ');
}

function formatAddressesHtml(addresses) {
    if (!addresses || !addresses.length) {
        return false;
    }
    let list = [];
    for (let address of addresses) {
        let entry = formatAddressHtml(address);
        if (entry) {
            list.push(entry);
        }
    }
    if (!list.length) {
        return false;
    }
    return list.join(', ');
}

function formatAddressPlain(addr) {
    if (!addr || (!addr.name && !addr.address)) {
        return false;
    }

    let parts = [];
    if (addr.name) {
        parts.push(addr.name);
    }

    if (addr.address) {
        parts.push(`<${addr.address}>`);
    }

    return parts.join(' ');
}

function formatAddressesPlain(addresses) {
    if (!addresses || !addresses.length) {
        return false;
    }
    let list = [];
    for (let address of addresses) {
        let entry = formatAddressPlain(address);
        if (entry) {
            list.push(entry);
        }
    }
    if (!list.length) {
        return false;
    }
    return list.join(', ');
}

function convertPlainToHtml(text) {
    let lines = text.split(/\r?\n/);

    let tree = {
        type: 'text',
        children: []
    };

    let createNode = (parent, type) => {
        let node = {
            parent,
            type,
            lines: [],
            children: []
        };
        parent.children.push(node);
        return node;
    };

    let walkNode = (curNode, lines) => {
        for (let line of lines) {
            if (/^>/.test(line)) {
                if (curNode.type !== 'quote') {
                    curNode = createNode(curNode.parent, 'quote');
                }
                curNode.lines.push(line.replace(/^> ?/, ''));
            } else if (curNode.type === 'quote') {
                // process child

                let quoteNode = curNode;

                let childNode = createNode(curNode, 'text');
                walkNode(childNode, quoteNode.lines);

                curNode = createNode(curNode.parent, 'text');
                curNode.lines.push(line);
            } else {
                curNode.lines.push(line);
            }
        }

        if (curNode.type === 'quote') {
            // process child

            let quoteNode = curNode;

            let childNode = createNode(curNode, 'text');
            walkNode(childNode, quoteNode.lines);
        }
    };

    let rootNode = createNode(tree, 'text');
    walkNode(rootNode, lines);

    function encodeTextPart(text) {
        try {
            let links = linkify.match(text);
            if (links && links.length) {
                let parts = [];
                let cursor = 0;
                for (let link of links) {
                    if (cursor < link.index) {
                        parts.push({
                            type: 'text',
                            content: text.substring(cursor, link.index)
                        });
                        cursor = link.index;
                    }
                    parts.push(Object.assign({ type: 'link' }, link));
                    cursor = link.lastIndex;
                }

                if (cursor < text.length) {
                    parts.push({
                        type: 'text',
                        content: text.substr(cursor)
                    });
                }

                return parts
                    .map(part => {
                        switch (part.type) {
                            case 'text':
                                return he.encode(part.content, { useNamedReferences: true });
                            case 'link':
                                return `<a href="${he.encode(part.url, { useNamedReferences: true })}">${he.encode(part.text, {
                                    useNamedReferences: true
                                })}</a>`;
                        }
                        return '';
                    })
                    .join('');
            }
        } catch (err) {
            // ignore?
        }

        return he.encode(text, { useNamedReferences: true });
    }

    function addHtmlTags(lines) {
        let textparts = ['<p>'];
        for (let i = 0; i < lines.length; i++) {
            let line = lines[i];

            if (!line.trim()) {
                if (i && lines[i - 1].trim()) {
                    textparts.push('</p><p>');
                }
            } else if (i < lines.length - 1 && lines[i + 1].trim()) {
                textparts.push(`${encodeTextPart(line)}<br />`);
            } else {
                textparts.push(`${encodeTextPart(line)}`);
            }
        }

        return textparts.join('\n') + '</p>';
    }

    let blc = 0;
    function paintNode(curNode, level) {
        let entries = [];
        level = (level || 0) + 1;

        if (curNode.type === 'text') {
            for (let child of curNode.children) {
                let content = paintNode(child);
                if (typeof content === 'string') {
                    entries.push(content);
                }
            }

            if (curNode.lines && curNode.lines.length) {
                entries.push(addHtmlTags(curNode.lines));
            }
        }

        if (curNode.type === 'quote') {
            for (let child of curNode.children) {
                let content = paintNode(child, level);
                if (typeof content === 'string') {
                    let id = ++blc;
                    entries.push(`
<blockquote type="cite" class="ee-block-${level}"><!-- blocquote ${id} start-->
${content}
</blockquote><!-- blocquote ${id} end-->`);
                }
            }
        }

        if (entries.length) {
            return entries.join('\n');
        }
    }

    return beautifyHtml(paintNode(tree));
}

function convertHtmlToPlain(html) {
    try {
        if (html && html.length < MAX_HTML_PARSE_LENGTH) {
            let text = htmlToText(html);
            return text.trim();
        }
    } catch (E) {
        // ignore
    }
    return false;
}

function escapePlain(text) {
    return '> ' + text.replace(/\r?\n/g, '\n> ');
}

function inlineMessagePlain(type, messageContent, messageData) {
    messageContent = (messageContent || '').toString();

    let originalBody;
    if (messageData.text && !messageData.text.plain && messageData.text.html) {
        originalBody = convertHtmlToPlain(messageData.text.html);
    } else {
        originalBody = messageData.text && messageData.text.plain;
    }

    if (!originalBody) {
        return messageContent;
    }

    let headerLines = [];

    if (messageData.from) {
        let entry = {
            title: 'From',
            content: formatAddressPlain(messageData.from) || '<>'
        };
        headerLines.push(entry);
    }

    if (messageData.subject) {
        let entry = {
            title: 'Subject',
            content: messageData.subject
        };
        headerLines.push(entry);
    }

    let dateHeader;
    if (messageData.headers && messageData.headers.date) {
        dateHeader = ([].concat(messageData.headers.date || []).shift() || '').toString().trim();
        if (dateHeader) {
            let entry = {
                title: 'Date',
                content: dateHeader
            };
            headerLines.push(entry);
        }
    }

    for (let key of ['to', 'cc', 'bcc']) {
        if (messageData[key]) {
            let content = formatAddressesPlain(messageData[key]);
            if (content) {
                let entry = {
                    title: key.replace(/^./, c => c.toUpperCase()),
                    content
                };
                headerLines.push(entry);
            }
        }
    }

    let headers = [];

    switch (type) {
        case 'forward':
            headers.push('Begin forwarded message:\n');

            for (let line of headerLines) {
                headers.push(`${line.title}: ${line.content}`);
            }
            break;
        case 'reply':
            headers.push(`On ${dateHeader || ''}, ${formatAddressPlain(messageData.from) || '<>'} wrote:\n`);
            break;
    }

    return `${messageContent}

${escapePlain(headers.join('\n'))}
>
${escapePlain(originalBody)}`;
}

function inlineMessageHtml(action, messageContent, messageData) {
    messageContent = (messageContent || '').toString();

    let originalBody;

    if (messageData.text && !messageData.text.html && messageData.text.plain) {
        originalBody = convertPlainToHtml(messageData.text.plain);
    } else {
        originalBody = getHtmlBody(messageData.text && messageData.text.html);
    }

    if (!originalBody) {
        return messageContent;
    }

    // remove html headers and stuff
    messageContent = getHtmlBody(messageContent);

    let headerLines = [];

    if (messageData.from) {
        let entry = {
            title: 'From',
            content: formatAddressHtml(messageData.from) || he.encode('<>', { useNamedReferences: true })
        };
        headerLines.push(entry);
    }

    if (messageData.subject) {
        let entry = {
            title: 'Subject',
            content: `<b class="">${he.encode(messageData.subject, { useNamedReferences: true })}</b>`
        };
        headerLines.push(entry);
    }

    let dateHeader;
    if (messageData.headers && messageData.headers.date) {
        dateHeader = ([].concat(messageData.headers.date || []).shift() || '').toString().trim();
        if (dateHeader) {
            let entry = {
                title: 'Date',
                content: he.encode(dateHeader, { useNamedReferences: true })
            };
            headerLines.push(entry);
        }
    }

    for (let key of ['to', 'cc', 'bcc']) {
        if (messageData[key]) {
            let content = formatAddressesHtml(messageData[key]);
            if (content) {
                let entry = {
                    title: key.replace(/^./, c => c.toUpperCase()),
                    content
                };
                headerLines.push(entry);
            }
        }
    }

    let headers = [];

    switch (action) {
        case 'forward':
            headers.push(`<div class="">Begin forwarded message:</div><br class="Apple-interchange-newline">`);

            for (let line of headerLines) {
                headers.push(
                    `<div style="margin-top: 0px; margin-right: 0px; margin-bottom: 0px; margin-left: 0px;" class=""><span style="font-family: -webkit-system-font, Helvetica Neue, Helvetica, sans-serif; color:rgba(0, 0, 0, 1.0);" class=""><b class="">${line.title}: </b></span><span style="font-family: -webkit-system-font, Helvetica Neue, Helvetica, sans-serif;" class="">${line.content}<br class=""></span></div>`
                );
            }
            break;
        case 'reply':
            headers.push(
                `<div class="">On ${he.encode(dateHeader || '', { useNamedReferences: true })}, ${
                    formatAddressHtml(messageData.from) || he.encode('<>', { useNamedReferences: true })
                } wrote:</div>`
            );
            break;
    }

    return `<html>

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
</head>

<body style="word-wrap: break-word; -webkit-nbsp-mode: space; line-break: after-white-space;" class="">${messageContent}<br class="">
    <div><br class="">
        <blockquote type="cite" class="ee-block-1">
${headers.join('\n')}<br class="">
            <div class="">${originalBody}</div>
        </blockquote>
    </div>
</body>

</html>`;
}

function inlineMessage(action, textType, messageContent, messageData) {
    switch (textType) {
        case 'html':
            return inlineMessageHtml(action, messageContent, messageData);
        case 'plain':
            return inlineMessagePlain(action, messageContent, messageData);
        default:
            return messageContent;
    }
}

module.exports = inlineMessage;
