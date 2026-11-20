'use strict';

/* global document, CSSStyleSheet */

// The `test` every e2e spec imports: Playwright's own, with CSS transitions and animations switched
// off in every page the spec opens.
//
// The admin UI's dialogs, dropdowns and tooltips are FlyonUI (HSOverlay and friends), which finishes
// opening and closing a component on `transitionend`. A click or key press that lands during that
// fade is swallowed, and a dialog closed mid-fade can keep its backdrop, which then intercepts every
// later click on the page until the test times out. That was the whole family of pages-admin.spec.js
// flakes (add-account, the tokens and internals dialogs, the AI page's test-filter dialog, the
// dashboard after a dialog), each of which a waiting helper only ever narrowed. FlyonUI's
// afterTransition() runs its callback at once when an element has no transition, so with motion off
// every open and close completes in the same task and there is no window left to land in.
//
// The rule goes in as a constructable stylesheet rather than a <style> element, because the admin
// Content-Security-Policy only admits stylesheets that carry the request's nonce, and the security
// header specs depend on that policy staying enforced (`bypassCSP` would hollow them out). Adopted
// stylesheets are CSSOM, which CSP does not govern.
//
// What is lost is nothing the specs assert: the fade itself. A spec that ever needs real motion can
// import from '@playwright/test' directly.

const base = require('@playwright/test');

const NO_MOTION = '*, *::before, *::after { transition: none !important; animation: none !important; }';

function stillPage(css) {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(css);
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
}

const test = base.test.extend({
    context: async ({ context }, use) => {
        await context.addInitScript(stillPage, NO_MOTION);
        await use(context);
    }
});

// For specs whose page waits on a live mailbox (the message browser opening an Ethereal message).
// Opening a message is several IMAP round trips in sequence, and the widget's folder counters (one
// STATUS per folder) share the connection. From a CI runner a round trip to Ethereal takes 120 to
// 280ms, so an open there regularly runs past the default 5 seconds while taking well under one
// locally. A spec that fails on that then deletes its account in cleanup, under the request still
// in flight, which turns up in the server log as a 503 "Connection not available" or a 404 for the
// message rather than as the slow open it was.
const liveMailboxExpect = base.expect.configure({ timeout: 30000 });

module.exports = Object.assign({}, base, { test, liveMailboxExpect });
