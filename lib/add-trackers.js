'use strict';

const msgpack = require('msgpack5')();
const { rewriteTextNodes } = require('./rewrite-text-nodes');

async function addOpenTracker(html, identifier, baseUrl) {
    // add open tracker

    const openTrackUrl = new URL('open.gif', baseUrl);
    openTrackUrl.searchParams.append('msg', identifier);

    const openTracker = `<img src="${openTrackUrl.href}" style="border: 0px; width:1px; height: 1px;" tabindex="-1" width="1" height="1" alt="">`;
    const bodyEndTagMatch = html.match(/<\/body/i);

    if (!bodyEndTagMatch) {
        // append to HTML content
        html += openTracker;
    } else {
        // paste in front of the body end tag
        html = html.substr(0, bodyEndTagMatch.index) + openTracker + html.substr(bodyEndTagMatch.index);
    }

    return html;
}

async function addClickTrackers(html, identifier, baseUrl) {
    // add click trackers

    html = html.replace(/(<a[^>]* href\s*=[\s"']*)(http[^"'>\s]+)/gi, (match, prefix, url) => {
        const redirectUrl = new URL('redirect', baseUrl);

        redirectUrl.searchParams.append('msg', identifier);
        redirectUrl.searchParams.append('url', url);

        return prefix + redirectUrl.href;
    });

    return html;
}

async function addTrackers(raw, account, messageId, baseUrl) {
    let identifier = msgpack.encode([account, messageId]).toString('base64url');

    let openTrackerAdded = false;
    return await rewriteTextNodes(raw, {
        async htmlRewriter(html) {
            if (!openTrackerAdded) {
                html = await addOpenTracker(html, identifier, baseUrl);
                openTrackerAdded = true;
            }
            html = await addClickTrackers(html, identifier, baseUrl);
            return html;
        }
    });
}

module.exports = { addTrackers };
