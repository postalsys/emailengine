'use strict';

const he = require('he');

const { rewriteTextNodes } = require('./rewrite-text-nodes');

const { getSignedFormDataSync, getServiceSecret } = require('./tools');

async function addOpenTracker(html, account, messageId, baseUrl) {
    // add open tracker

    const serviceSecret = await getServiceSecret();

    const openTrackUrl = new URL('open.gif', baseUrl);

    let { data, signature } = getSignedFormDataSync(
        serviceSecret,
        {
            act: 'open',
            acc: account,
            msg: messageId
        },
        true
    );

    openTrackUrl.searchParams.append('data', data);
    if (signature) {
        openTrackUrl.searchParams.append('sig', signature);
    }

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

async function addClickTrackers(html, account, messageId, baseUrl) {
    // add click trackers

    const serviceSecret = await getServiceSecret();

    html = html.replace(/(<a[^>]* href\s*=[\s"']*)(http[^"'>\s]+)/gi, (match, prefix, url) => {
        const redirectUrl = new URL('redirect', baseUrl);

        try {
            url = he.decode(url);
        } catch (err) {
            // ???
        }

        // check if we need to rewrite the URL
        try {
            let parsedUrl = new URL(url);
            if (parsedUrl.origin === redirectUrl.origin) {
                switch (parsedUrl.pathname) {
                    case '/unsubscribe':
                    case '/redirect':
                        // do not rewrite the URL
                        return match;
                }
            }
        } catch (err) {
            // ???
        }

        let { data, signature } = getSignedFormDataSync(
            serviceSecret,
            {
                act: 'click',
                url,
                acc: account,
                msg: messageId
            },
            true
        );

        redirectUrl.searchParams.append('data', data);
        if (signature) {
            redirectUrl.searchParams.append('sig', signature);
        }

        return (
            prefix +
            he.encode(redirectUrl.href, {
                useNamedReferences: true
            })
        );
    });

    return html;
}

async function addTrackers(raw, account, messageId, baseUrl, opts) {
    let { trackClicks, trackOpens } = opts || {};
    let openTrackerAdded = false;
    return await rewriteTextNodes(raw, {
        async htmlRewriter(html) {
            if (trackOpens && !openTrackerAdded) {
                html = await addOpenTracker(html, account, messageId, baseUrl);
                openTrackerAdded = true;
            }

            if (trackClicks) {
                html = await addClickTrackers(html, account, messageId, baseUrl);
            }
            return html;
        }
    });
}

module.exports = { addTrackers };
