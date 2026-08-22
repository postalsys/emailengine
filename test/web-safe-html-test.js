'use strict';

// Unit tests for lib/web-safe-html.js. The module needs no Redis and no network - it runs the
// content extractor and the sanitizer over message bodies supplied here.

const test = require('node:test');
const assert = require('node:assert').strict;

const { messageWebSafeHtml, webSafeTextResponse, applyWebSafeHtmlOptions, collapseThreadHistory } = require('../lib/web-safe-html');
const { COLLAPSE_CLASS, COLLAPSE_TOGGLE_CLASS } = require('../lib/consts');

const MARKER = `<details class="${COLLAPSE_CLASS}">`;

// A Gmail reply: new content and a signature in one container, the quoted thread in a sibling
// gmail_quote container.
const gmailReply = {
    subject: 'Re: Deploy window',
    from: { name: 'Alice Smith', address: 'alice@example.com' },
    inReplyTo: '<parent@example.net>',
    text: {
        html:
            '<html><head><style>p{color:red}</style></head><body><div dir="ltr">Yes, Monday works for me. Let us start at 09:00 so the team has the whole day.' +
            '<div><br></div><div>Thanks,<br>Alice</div></div><br>' +
            '<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Fri, Jul 25, 2026 at 10:12 AM Bob &lt;bob@example.net&gt; wrote:<br></div>' +
            '<blockquote class="gmail_quote" style="margin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex"><div dir="ltr">' +
            'Can we meet on Monday to walk through the deploy plan?<div>Also, should I bring the incident report from last week?</div>' +
            '<div>I can push it back to Tuesday if that suits everyone better.</div></div></blockquote></div></body></html>',
        plain:
            'Yes, Monday works for me. Let us start at 09:00 so the team has the whole day.\n\nThanks,\nAlice\n\n' +
            'On Fri, Jul 25, 2026 at 10:12 AM Bob <bob@example.net> wrote:\n' +
            '> Can we meet on Monday to walk through the deploy plan?\n' +
            '> Also, should I bring the incident report from last week?\n' +
            '> I can push it back to Tuesday if that suits everyone better.\n'
    }
};

// An Outlook reply: everything, including the quoted thread, lives inside a single WordSection1
// container, so the cut point is nested rather than at the top level.
const outlookReply = {
    subject: 'RE: Invoice 4432',
    from: { name: 'Carol', address: 'carol@example.org' },
    inReplyTo: '<inv@example.net>',
    text: {
        html:
            '<html><body lang="EN-GB"><div class="WordSection1"><p class="MsoNormal">Approved, please go ahead and pay it this week.</p>' +
            '<p class="MsoNormal">&nbsp;</p><p class="MsoNormal">Carol</p>' +
            '<div style="border:none;border-top:solid #E1E1E1 1.0pt;padding:3.0pt 0cm 0cm 0cm"><p class="MsoNormal"><b>From:</b> Dave &lt;dave@example.net&gt;<br>' +
            '<b>Sent:</b> 24 July 2026 09:04<br><b>To:</b> Carol &lt;carol@example.org&gt;<br><b>Subject:</b> Invoice 4432</p></div>' +
            '<p class="MsoNormal">&nbsp;</p><p class="MsoNormal">Hi Carol, attached is invoice 4432 for the June retainer. ' +
            'Could you confirm it is approved so accounts can schedule the payment run?</p></div></body></html>'
    }
};

// A plain text only reply. There is no HTML part to read quote structure out of, so the text is
// what gets analysed.
const plainTextReply = {
    subject: 'Re: Server migration',
    from: { name: 'Erin', address: 'erin@example.com' },
    inReplyTo: '<mig@example.net>',
    text: {
        plain:
            'Sounds good, let us do the cutover on Saturday morning.\n\nI will send the runbook tomorrow.\n\n' +
            'On Thu, 24 Jul 2026, Frank <frank@example.net> wrote:\n' +
            '> When do you want to do the server migration? The maintenance window\n' +
            '> closes at the end of the month, so we are running out of weekends.\n>\n' +
            '> I can be around all Saturday if that helps.\n>\n> Frank\n'
    }
};

test('collapseThreadHistory', async t => {
    t.after(() => {
        // lib/web-safe-html reads its env flag through lib/tools, which transitively pulls in
        // lib/settings -> lib/db and opens Redis sockets that keep the event loop alive after the
        // tests finish. Force-exit so node:test's runner does not hang waiting for it to drain.
        setTimeout(() => process.exit(), 500).unref();
    });

    await t.test('folds the quoted thread of an HTML reply into one marker', async () => {
        const collapsed = await collapseThreadHistory(gmailReply);

        assert.ok(collapsed, 'expected the reply to be collapsible');
        assert.equal(collapsed.html.split(MARKER).length - 1, 1, 'expected exactly one marker');
        assert.equal(collapsed.html.split('</details>').length - 1, 1);

        // The marker opens on the quote container and leaves everything the sender wrote in front
        // of it, signature included.
        const [visible, hidden] = collapsed.html.split(MARKER);
        assert.match(visible, /Yes, Monday works for me/);
        assert.match(visible, /Thanks,<br>Alice/);
        assert.doesNotMatch(visible, /walk through the deploy plan/);
        assert.match(hidden, /walk through the deploy plan/);
        assert.match(hidden, /Also, should I bring the incident report/);
    });

    await t.test('leaves the toggle empty for the renderer to label', async () => {
        const collapsed = await collapseThreadHistory(gmailReply);

        assert.ok(collapsed);
        assert.match(collapsed.html, new RegExp(`<summary class="${COLLAPSE_TOGGLE_CLASS}"></summary>`));
    });

    await t.test('folds a nested cut point, where the quote shares a container with the reply', async () => {
        const collapsed = await collapseThreadHistory(outlookReply);

        assert.ok(collapsed, 'expected the reply to be collapsible');

        const [visible, hidden] = collapsed.html.split(MARKER);
        assert.match(visible, /Approved, please go ahead/);
        assert.doesNotMatch(visible, /invoice 4432 for the June retainer/);
        assert.match(hidden, /<b>From:<\/b> Dave/);
        assert.match(hidden, /invoice 4432 for the June retainer/);
    });

    await t.test('analyses the plain text body when there is no HTML part', async () => {
        const collapsed = await collapseThreadHistory(plainTextReply);

        assert.ok(collapsed, 'expected the reply to be collapsible');

        const [visible, hidden] = collapsed.html.split(MARKER);
        assert.match(visible, /cutover on Saturday morning/);
        assert.doesNotMatch(visible, /maintenance window/);
        assert.match(hidden, /When do you want to do the server migration/);
        // Quoted lines still become blockquotes, and the styling mimeHtml applies to plain text
        // bodies travels with them.
        assert.match(hidden, /<blockquote/);
        assert.match(collapsed.html, /font-family: sans-serif/);
    });

    await t.test('normalizes CRLF text so the cut lands where the extractor reported it', async () => {
        const collapsed = await collapseThreadHistory({
            subject: 'Re: CRLF',
            from: { name: 'Pia', address: 'pia@example.com' },
            inReplyTo: '<crlf@example.net>',
            text: {
                plain:
                    'Yes that works.\r\n\r\nOn Thu, 24 Jul 2026, Quinn <quinn@example.net> wrote:\r\n' +
                    '> Can we push the review to Thursday? I have not had a chance to read\r\n' +
                    '> through the whole design document yet, and I would rather not skim it.\r\n>\r\n> Quinn\r\n'
            }
        });

        assert.ok(collapsed, 'expected the reply to be collapsible');

        const [visible, hidden] = collapsed.html.split(MARKER);
        assert.match(visible, /Yes that works/);
        assert.doesNotMatch(visible, /push the review to Thursday/);
        assert.match(hidden, /push the review to Thursday/);
    });

    await t.test('leaves a message with nothing quoted alone', async () => {
        const collapsed = await collapseThreadHistory({
            subject: 'Lunch?',
            from: { name: 'Greg', address: 'greg@example.com' },
            text: {
                html: '<html><body><div>Hey, are you around for lunch today? I was thinking of the place near the office at half twelve.</div></body></html>',
                plain: 'Hey, are you around for lunch today? I was thinking of the place near the office at half twelve.'
            }
        });

        assert.equal(collapsed, null);
    });

    await t.test('leaves a message that is nothing but quoted history alone', async () => {
        // Folding this one would hide the entire message behind a control.
        const collapsed = await collapseThreadHistory({
            subject: 'Fwd: nothing added',
            from: { name: 'Hank', address: 'hank@example.com' },
            text: {
                html:
                    '<html><body><div class="gmail_quote"><div class="gmail_attr">On Fri, Jul 25, 2026 at 10:12 AM Bob &lt;bob@example.net&gt; wrote:<br></div>' +
                    '<blockquote class="gmail_quote"><div>Can we meet on Monday to walk through the deploy plan? ' +
                    'Also, should I bring the incident report?</div></blockquote></div></body></html>'
            }
        });

        assert.equal(collapsed, null);
    });

    await t.test('leaves a tail too short to be worth a control alone', async () => {
        const collapsed = await collapseThreadHistory({
            subject: 'Re: Ping',
            from: { name: 'Ida', address: 'ida@example.com' },
            inReplyTo: '<ping@example.net>',
            text: { plain: 'Got it, thanks.\n\nOn Thu, 24 Jul 2026, Jo <jo@example.net> wrote:\n> Ping?\n' }
        });

        assert.equal(collapsed, null);
    });

    await t.test('skips cut points inside a table, where a wrapper can not be placed', async () => {
        const collapsed = await collapseThreadHistory({
            subject: 'Re: Table layout',
            from: { name: 'Ravi', address: 'ravi@example.com' },
            inReplyTo: '<t@example.net>',
            text: {
                html:
                    '<html><body><table><tr><td><div>Yes, that is fine by me.</div></td></tr>' +
                    '<tr><td><div class="gmail_quote"><div class="gmail_attr">On Fri, Jul 25, 2026 Sam &lt;sam@example.net&gt; wrote:<br></div>' +
                    '<blockquote class="gmail_quote"><div>Are you happy with the new layout, or should we revert to the single column ' +
                    'version we had before?</div></blockquote></div></td></tr></table></body></html>'
            }
        });

        assert.equal(collapsed, null);
    });

    await t.test('leaves the HTML body alone when the extractor could only read the text part', async () => {
        // The HTML part here is a stub, so the extractor classifies the text instead. Folding on
        // that would mean rendering the message from the text and discarding the sender's markup.
        const collapsed = await collapseThreadHistory({
            subject: 'Re: Stub HTML part',
            from: { name: 'Sven', address: 'sven@example.com' },
            inReplyTo: '<stub@example.net>',
            text: {
                html: '<html><body><div><img src="https://example.com/pixel.gif"></div></body></html>',
                plain:
                    'Confirmed, the numbers match what we have here.\n\n' +
                    'On Thu, 24 Jul 2026, Tess <tess@example.net> wrote:\n' +
                    '> Could you check the reconciliation report before the board meeting?\n' +
                    '> The totals in the summary tab do not match the ledger export.\n>\n> Tess\n'
            }
        });

        assert.equal(collapsed, null);
    });

    await t.test('leaves an oversized body unfolded rather than analysing part of it', async () => {
        const filler = 'Some ordinary sentence that the sender wrote themselves. '.repeat(6000);
        const collapsed = await collapseThreadHistory({
            subject: 'Re: Long thread',
            from: { name: 'Uma', address: 'uma@example.com' },
            inReplyTo: '<long@example.net>',
            text: {
                plain:
                    `${filler}\n\nOn Thu, 24 Jul 2026, Vic <vic@example.net> wrote:\n` +
                    '> Could you check the reconciliation report before the board meeting?\n' +
                    '> The totals in the summary tab do not match the ledger export.\n>\n> Vic\n'
            }
        });

        assert.equal(collapsed, null);
    });

    await t.test('leaves an empty message alone', async () => {
        assert.equal(await collapseThreadHistory({ text: { html: '', plain: '' } }), null);
        assert.equal(await collapseThreadHistory({ text: { html: '<html><body>   </body></html>', plain: '   ' } }), null);
        assert.equal(await collapseThreadHistory({ text: {} }), null);
        assert.equal(await collapseThreadHistory({}), null);
    });
});

test('messageWebSafeHtml', async t => {
    await t.test('keeps the marker through sanitization', async () => {
        const html = await messageWebSafeHtml(gmailReply);

        assert.match(html, new RegExp(`<details class="${COLLAPSE_CLASS}"`));
        assert.match(html, new RegExp(`<summary class="${COLLAPSE_TOGGLE_CLASS}"></summary>`));
        assert.match(html, /<\/details>/);
        // Both halves are still present. Nothing is dropped, only folded.
        assert.match(html, /Yes, Monday works for me/);
        assert.match(html, /walk through the deploy plan/);
    });

    await t.test('still sanitizes the folded half', async () => {
        const html = await messageWebSafeHtml({
            subject: 'Re: Deploy window',
            from: { name: 'Mallory', address: 'mallory@example.net' },
            inReplyTo: '<parent@example.net>',
            text: {
                html:
                    '<html><body><div dir="ltr">Monday is fine by me, see you then.</div><br>' +
                    '<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Fri, Jul 25, 2026 Bob &lt;bob@example.net&gt; wrote:<br></div>' +
                    '<blockquote class="gmail_quote"><div onclick="alert(1)">Can we meet on Monday to walk through the deploy plan? ' +
                    'I would like to have the incident report to hand as well.<script>alert(2)</script></div></blockquote></div></body></html>'
            }
        });

        assert.match(html, new RegExp(`<details class="${COLLAPSE_CLASS}"`));
        assert.doesNotMatch(html, /onclick/);
        assert.doesNotMatch(html, /<script/);
    });

    await t.test('sanitizes a message that has nothing to fold', async () => {
        const html = await messageWebSafeHtml({
            subject: 'Hello',
            text: { html: '<html><body><div onclick="alert(1)">Hello there</div><script>alert(2)</script></body></html>' }
        });

        assert.doesNotMatch(html, new RegExp(COLLAPSE_CLASS));
        assert.doesNotMatch(html, /onclick/);
        assert.doesNotMatch(html, /<script/);
        assert.match(html, /Hello there/);
    });
});

test('webSafeTextResponse', async t => {
    await t.test('returns one rendering and drops the plaintext twin', async () => {
        const response = await webSafeTextResponse({
            html: '<html><body><div>Hello there</div></body></html>',
            plain: 'Hello there',
            hasMore: false
        });

        assert.equal(response.webSafe, true);
        assert.equal(response.hasMore, false);
        assert.match(response.html, /Hello there/);
        // The whole point: the caller is not handed the same message twice
        assert.ok(!('plain' in response), 'the plaintext part must not be returned beside the generated HTML');
    });

    await t.test('generates HTML for a message that carries only a plaintext part', async () => {
        const response = await webSafeTextResponse({ plain: 'Hello there', hasMore: true });

        assert.equal(response.webSafe, true);
        assert.equal(response.hasMore, true);
        assert.match(response.html, /Hello there/);
    });

    await t.test('folds the quoted thread, so the boundary survives into the response', async () => {
        const response = await webSafeTextResponse({ html: gmailReply.text.html, plain: gmailReply.text.plain });

        assert.match(response.html, new RegExp(`<details class="${COLLAPSE_CLASS}"`));
        assert.match(response.html, /Yes, Monday works for me/);
        assert.match(response.html, /walk through the deploy plan/);
    });

    await t.test('leaves a response with no body alone', async () => {
        // An empty `html` marked web-safe would claim more than the message says
        assert.deepEqual(await webSafeTextResponse({ hasMore: false }), { hasMore: false });
        assert.equal(await webSafeTextResponse(null), null);
    });
});

test('webSafeHtml option expansion', async t => {
    await t.test('expands the shorthand into the options it stands for', () => {
        assert.deepEqual(applyWebSafeHtmlOptions({ webSafeHtml: true }), {
            webSafeHtml: true,
            textType: '*',
            preProcessHtml: true,
            embedAttachedImages: true
        });
    });

    await t.test('an explicit embedAttachedImages=false wins over the shorthand', () => {
        // The point of the override: keep the sanitizing and the single rendering, leave the
        // `cid:` references alone rather than inlining every referenced attachment as a data URI
        const options = applyWebSafeHtmlOptions({ webSafeHtml: true, embedAttachedImages: false });

        assert.equal(options.embedAttachedImages, false);
        assert.equal(options.textType, '*');
        assert.equal(options.preProcessHtml, true);
    });

    await t.test('resolves the tri-state to a boolean either way', () => {
        // The query schema deliberately carries no default so that absent stays distinguishable
        // from an explicit false. That distinction is spent here, so the four backends that read
        // the flag never see the undefined.
        assert.equal(applyWebSafeHtmlOptions({}).embedAttachedImages, false);
        assert.equal(applyWebSafeHtmlOptions({ textType: 'html' }).embedAttachedImages, false);
        assert.equal(applyWebSafeHtmlOptions({ embedAttachedImages: true }).embedAttachedImages, true);
    });

    await t.test('leaves the rendering options alone when the shorthand was not asked for', () => {
        assert.deepEqual(applyWebSafeHtmlOptions({ textType: 'html' }), { textType: 'html', embedAttachedImages: false });
    });

    await t.test('is idempotent, so a facade and a backend can both call it', () => {
        // Account.getMessage expands, and the Gmail and Graph clients expand again on the same
        // path - the second call has to be a no-op rather than a second policy
        const once = applyWebSafeHtmlOptions({ webSafeHtml: true, embedAttachedImages: false });
        assert.deepEqual(applyWebSafeHtmlOptions(Object.assign({}, once)), once);
    });
});
