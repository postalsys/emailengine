'use strict';

// Client behavior for the server-rendered API reference (/admin/reference).
//
// The page arrives as finished HTML - operations, schemas, examples and code samples
// are all rendered by lib/api-reference/ on the server. Nothing here builds page
// content; this file only adds what genuinely needs a browser: deferred syntax
// highlighting, the sidebar filter and its keyboard handling, opening the collapsed
// groups a property deep link lands in, remembering the reader's code sample language,
// and the try-it request runner.

(() => {
    // Responses larger than this are truncated before being inserted into the DOM.
    // A message export or a full settings dump can be megabytes, and highlighting
    // that much text locks up the tab.
    const MAX_RESPONSE_CHARS = 200000;

    // Shape of the curl command copied from a try-it panel. Both match
    // lib/api-reference/code-samples.js, so a copied command is indistinguishable from the
    // generated curl sample above the same operation.
    const TOKEN_ENV_VAR = 'EMAILENGINE_TOKEN';
    const INDENT = '    ';

    // The try-it token, shared by every reference page.
    //
    // sessionStorage, not localStorage: the point is to survive navigation between the
    // overview and the group pages, which it does, while the credential still dies with
    // the tab. A minted token only lives an hour anyway, and an access token in permanent
    // storage is an exfiltration target for any future XSS on the admin UI.
    const TOKEN_KEY = 'eeRefToken';

    const tokenStore = {
        read() {
            let raw;
            try {
                raw = window.sessionStorage.getItem(TOKEN_KEY);
            } catch (err) {
                return null; // storage blocked (private mode, cookie policy)
            }
            if (!raw) {
                return null;
            }

            let entry;
            try {
                entry = JSON.parse(raw);
            } catch (err) {
                return null;
            }

            if (!entry || !entry.token || (entry.expires && Date.now() >= entry.expires)) {
                tokenStore.clear();
                return null;
            }
            return entry;
        },

        write(token, expires) {
            try {
                // `expires` doubles as the "this page minted it" marker: only the mint path
                // sets one, so a pasted token is exactly an entry without it
                window.sessionStorage.setItem(TOKEN_KEY, JSON.stringify({ token, expires: expires || null }));
            } catch (err) {
                // storage blocked - the token still works for this page load
            }
        },

        clear() {
            try {
                window.sessionStorage.removeItem(TOKEN_KEY);
            } catch (err) {
                // nothing to do
            }
        }
    };

    const minutesLeft = expires => Math.max(0, Math.round((expires - Date.now()) / 60000));

    // Repaints the always-visible status in the sidebar, and shows the Clear control on
    // the overview page only while there is something to clear.
    const paintTokenStatus = () => {
        const entry = tokenStore.read();

        const state = document.getElementById('ref-token-state');
        if (state) {
            state.textContent = entry ? (entry.expires ? `${minutesLeft(entry.expires)} min left` : 'Active') : 'Not set';
            state.className = entry ? 'text-success text-2xs' : 'text-base-content/50 text-2xs';
        }

        const clearWrap = document.getElementById('ref-token-clear-wrap');
        if (clearWrap) {
            clearWrap.classList.toggle('hidden', !entry);
        }

        // The "no token set" banner. It is only in the DOM when a token is actually
        // required (reference/token-alert.hbs skips it when `disableTokens` is on), so
        // its absence means there is nothing to warn about.
        const alert = document.getElementById('ref-token-alert');
        if (alert) {
            alert.classList.toggle('hidden', !!entry);
            alert.classList.toggle('flex', !entry);
        }
    };

    // A tag page carries up to ~150 code blocks, several of them tens of kilobytes,
    // so highlighting all of them up front stalls the page for seconds. Each block is
    // highlighted the first time it becomes visible instead. That also covers blocks
    // inside collapsed <details> and inactive tab panels for free: those have no
    // layout box until they open, so the observer fires exactly then.
    const highlightBlock = block => {
        if (block.dataset.eeHighlighted) {
            return;
        }
        block.dataset.eeHighlighted = '1';
        if (window.hljs) {
            window.hljs.highlightElement(block);
        }
    };

    const initHighlighting = () => {
        const blocks = document.querySelectorAll('pre code[class*="language-"]');
        if (!blocks.length) {
            return;
        }

        const observer = new IntersectionObserver(
            entries => {
                for (const entry of entries) {
                    if (entry.isIntersecting) {
                        highlightBlock(entry.target);
                        observer.unobserve(entry.target);
                    }
                }
            },
            { rootMargin: '200px' }
        );

        blocks.forEach(block => observer.observe(block));
    };

    // FlyonUI binds its component autoInit to the window `load` event, not DOMContentLoaded.
    // Anything that drives a tab has to wait for that: a click dispatched earlier lands on a
    // button whose handler is not attached yet and silently does nothing, which is exactly
    // how it fails - no error, the tab just stays where it was.
    const whenComponentsReady = fn => {
        if (document.readyState === 'complete') {
            fn();
            return;
        }
        window.addEventListener('load', fn);
    };

    // Deep links point at a single schema property ("#accountCreate.body.imap.tls"), which
    // can sit inside collapsed <details> groups and an inactive response tab - neither of
    // which the browser can scroll to, because they have no layout box. Everything on the
    // way down is opened first, then the row is scrolled into view. The highlight itself is
    // :target CSS and needs nothing here.
    const revealTarget = () => {
        // No decoding: every anchor the model emits is [A-Za-z0-9_.-], so the fragment and
        // the id are the same string, and anything else simply does not match an element
        const target = document.getElementById(window.location.hash.slice(1));
        if (!target) {
            return;
        }

        for (let element = target.parentElement; element; element = element.parentElement) {
            if (element.tagName === 'DETAILS') {
                element.open = true;
            }

            // Response and code-sample panels are plain hidden divs driven by the FlyonUI
            // tab plugin, so the tab button is what has to be activated. The panel already
            // names its button in aria-labelledby, so that is read rather than recomposing
            // ui/tab's "<target>-tab" id convention here.
            if (element.getAttribute('role') === 'tabpanel' && element.classList.contains('hidden')) {
                const tab = document.getElementById(element.getAttribute('aria-labelledby') || '');
                if (tab) {
                    tab.click();
                }
            }
        }

        target.scrollIntoView({ block: 'start' });
    };

    // Resolved once - the platform cannot change, and the shortcut check runs on every
    // keystroke anywhere on the page
    const IS_MAC = /mac/i.test((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '');

    // True while the caret is somewhere the user is typing, so a bare-letter shortcut
    // does not swallow the keystroke.
    const isEditable = element => !!element && (element.isContentEditable || /^(input|textarea|select)$/i.test(element.tagName));

    // Sidebar filter. Every operation is already in the DOM (hidden until the box has
    // input), so narrowing the list is plain matching - there is no index to fetch.
    // A hit matches on more than it shows: reference/nav.hbs puts the operation id and
    // every parameter and request-body property name in data-search, so "mailbox" finds
    // the endpoints that accept one, not just the ones with the word in their path.
    //
    // Keyboard navigation moves real DOM focus between the result links rather than
    // tracking a selected index behind aria-activedescendant. The results are already
    // links, so focus gives Enter-to-open, the browser's own focus ring and a correct
    // screen reader announcement for free, without claiming this is a listbox when the
    // markup is a list of links.
    const initFilter = () => {
        const input = document.getElementById('ref-filter');
        const results = document.getElementById('ref-filter-results');
        const tagList = document.getElementById('ref-tag-list');
        const empty = document.getElementById('ref-filter-empty');
        const hint = document.getElementById('ref-filter-hint');

        if (!input || !results || !tagList || !hint) {
            return;
        }

        const count = hint.querySelector('[role="status"]');

        // Resolved once: 82 rows, and the arrow keys would otherwise re-query the DOM for
        // every one of them on every keypress while a key is held down
        const hits = Array.from(results.querySelectorAll('.ee-ref-hit')).map(el => ({
            el,
            link: el.querySelector('a'),
            text: (el.dataset.search || '').toLowerCase()
        }));

        const visibleLinks = () => hits.filter(hit => !hit.el.classList.contains('hidden')).map(hit => hit.link);

        const apply = () => {
            const terms = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
            const filtering = terms.length > 0;

            tagList.classList.toggle('hidden', filtering);
            results.classList.toggle('hidden', !filtering);
            hint.classList.toggle('hidden', !filtering);
            hint.classList.toggle('flex', filtering);

            if (!filtering) {
                return;
            }

            let visible = 0;
            for (const hit of hits) {
                const match = terms.every(term => hit.text.includes(term));
                hit.el.classList.toggle('hidden', !match);
                if (match) {
                    visible++;
                }
            }

            empty.classList.toggle('hidden', visible > 0);
            count.textContent = `${visible} ${visible === 1 ? 'endpoint' : 'endpoints'}`;
        };

        // The input and the visible results form a single cycle, so moving up from the
        // first result - or down past the last - lands back in the field instead of
        // trapping focus in the list.
        const move = offset => {
            const links = visibleLinks();
            if (!links.length) {
                return;
            }

            const current = links.indexOf(document.activeElement);
            if (current < 0) {
                // focus is in the field: Down enters at the top, Up at the bottom
                links[offset > 0 ? 0 : links.length - 1].focus();
                return;
            }

            const next = current + offset;
            if (next < 0 || next >= links.length) {
                input.focus();
                return;
            }

            links[next].focus();
        };

        const reset = () => {
            input.value = '';
            apply();
        };

        // Shared by both listeners below - only their Escape behavior genuinely differs
        const arrowNav = event => {
            if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') {
                return false;
            }
            event.preventDefault();
            move(event.key === 'ArrowDown' ? 1 : -1);
            return true;
        };

        input.addEventListener('input', apply);

        input.addEventListener('keydown', event => {
            if (arrowNav(event)) {
                return;
            }

            if (event.key === 'Enter') {
                // Typing and pressing Enter opens the top hit, so the common case never
                // needs the arrow keys
                const [first] = visibleLinks();
                if (first) {
                    event.preventDefault();
                    first.click();
                }
                return;
            }

            if (event.key === 'Escape') {
                if (input.value) {
                    event.preventDefault();
                    reset();
                } else {
                    input.blur();
                }
            }
        });

        results.addEventListener('keydown', event => {
            if (arrowNav(event)) {
                return;
            }

            if (event.key === 'Escape') {
                event.preventDefault();
                input.focus();
            }
        });

        // Focus shortcuts. Ctrl+K (Cmd+K on macOS) is the common one; "/" matches what
        // most documentation sites bind, and is ignored while the caret is in a field so
        // it can still be typed into the filter itself.
        window.addEventListener('keydown', event => {
            const hotkey = (IS_MAC ? event.metaKey : event.ctrlKey) && !event.altKey && event.key.toLowerCase() === 'k';
            const slash = event.key === '/' && !event.metaKey && !event.ctrlKey && !event.altKey && !isEditable(document.activeElement);

            if (!hotkey && !slash) {
                return;
            }

            event.preventDefault();
            input.focus();
            input.select();
        });
    };

    // Code sample language, remembered across operations and page loads.
    //
    // localStorage, not sessionStorage (which is what the try-it token uses): this is a
    // display preference, not a credential, and losing it when the tab closes is exactly
    // the annoyance the setting exists to fix.
    //
    // The stored value is the sample's id (`curl`, `node`, `python`, `custom-0`), carried on
    // the button as data-tab-key. Not the label: that is display text, so rewording one
    // would silently reset everybody's choice, and a hand-written x-codeSamples tab labelled
    // "curl" would take the generated tab's place on operations that have both. An operation
    // that does not offer the remembered id - hand-written samples exist per operation - just
    // keeps its own default rather than landing on an unrelated tab.
    const SAMPLE_LANGUAGE_KEY = 'eeRefSampleLanguage';

    const initSampleTabs = () => {
        const groups = document.querySelectorAll('[data-sample-tabs]');
        if (!groups.length) {
            return;
        }

        let preferred;
        try {
            preferred = window.localStorage.getItem(SAMPLE_LANGUAGE_KEY);
        } catch (err) {
            preferred = null;
        }

        whenComponentsReady(() => {
            if (preferred) {
                for (const group of groups) {
                    const tab = group.querySelector(`[data-tab-key="${CSS.escape(preferred)}"]`);
                    if (tab && tab.getAttribute('aria-selected') !== 'true') {
                        tab.click();
                    }
                }
            }

            // Bound only after the restore pass, so those synthetic clicks do not each
            // rewrite the same value - a 13-operation page would otherwise fire a dozen
            // storage writes on load. Clicks before this point cannot reach a tab anyway:
            // FlyonUI is not initialized yet.
            document.addEventListener('click', event => {
                const tab = event.target.closest('[data-sample-tabs] [role="tab"]');
                if (!tab || !tab.dataset.tabKey) {
                    return;
                }

                try {
                    window.localStorage.setItem(SAMPLE_LANGUAGE_KEY, tab.dataset.tabKey);
                } catch (err) {
                    // storage blocked - the choice still applies to this page
                }
            });
        });
    };

    const badgeVariant = status => {
        if (status >= 200 && status < 300) {
            return 'badge-success';
        }
        if (status >= 400 && status < 500) {
            return 'badge-warning';
        }
        if (status >= 500) {
            return 'badge-error';
        }
        return 'badge-neutral';
    };

    const buildRequest = form => {
        let path = form.dataset.path;

        for (const input of form.querySelectorAll('[data-in="path"]')) {
            const value = input.value.trim();
            if (!value) {
                throw new Error(`Path parameter "${input.dataset.param}" is required`);
            }
            path = path.replace(`{${input.dataset.param}}`, encodeURIComponent(value));
        }

        const query = new URLSearchParams();
        for (const input of form.querySelectorAll('[data-in="query"]')) {
            const value = input.value.trim();
            if (value) {
                query.append(input.dataset.param, value);
            }
        }

        const headers = {};
        for (const input of form.querySelectorAll('[data-in="header"]')) {
            const value = input.value.trim();
            if (value) {
                headers[input.dataset.param] = value;
            }
        }

        // The token held for this tab, set once on the overview page. Only ever sent to
        // this instance's own API, by the request the user explicitly triggered.
        const entry = tokenStore.read();
        if (entry) {
            headers.Authorization = `Bearer ${entry.token}`;
        }

        let body;
        const bodyField = form.querySelector('[data-body]');
        if (bodyField && bodyField.value.trim()) {
            try {
                JSON.parse(bodyField.value);
            } catch (err) {
                throw new Error(`Request body is not valid JSON: ${err.message}`);
            }
            body = bodyField.value;
            headers['Content-Type'] = 'application/json';
        }

        const queryString = query.toString();

        return {
            url: path + (queryString ? `?${queryString}` : ''),
            method: (form.dataset.method || 'get').toUpperCase(),
            headers,
            body
        };
    };

    const renderResponse = async (form, response, elapsed) => {
        const result = form.querySelector('.ee-ref-try-result');
        const codeBadge = form.querySelector('.ee-ref-try-code');
        const timeEl = form.querySelector('.ee-ref-try-time');
        const bodyEl = form.querySelector('.ee-ref-try-body');

        codeBadge.className = `ee-ref-try-code badge badge-sm ${badgeVariant(response.status)}`;
        codeBadge.textContent = `${response.status} ${response.statusText}`.trim();

        const contentType = response.headers.get('content-type') || '';
        timeEl.textContent = `${elapsed} ms${contentType ? ` - ${contentType.split(';')[0]}` : ''}`;

        let text = await response.text();
        let truncated = false;
        if (text.length > MAX_RESPONSE_CHARS) {
            text = text.slice(0, MAX_RESPONSE_CHARS);
            truncated = true;
        }

        if (contentType.includes('json')) {
            try {
                text = JSON.stringify(JSON.parse(text), null, 2);
            } catch (err) {
                // a truncated or non-conforming body is shown as received
            }
        }

        if (truncated) {
            text += '\n\n... response truncated for display';
        }

        // textContent, never innerHTML: the body is whatever the API returned
        bodyEl.textContent = text;
        delete bodyEl.dataset.eeHighlighted;
        bodyEl.removeAttribute('data-highlighted');
        result.classList.remove('hidden');
        highlightBlock(bodyEl);
    };

    // Single-quoted shell strings cannot contain a single quote, so each one closes the
    // string, adds an escaped quote and reopens it. Mirrors shellQuote() in
    // lib/api-reference/code-samples.js, which does the same for the generated samples.
    const shellQuote = value => `'${String(value).replace(/'/g, `'\\''`)}'`;

    // Serializes the request the form would actually send as a runnable curl command. The
    // generated samples above an operation come from its schema examples, so they drift
    // from the form as soon as anything is edited; this is built from the same
    // buildRequest() the Send button uses, so the two cannot disagree.
    //
    // The access token is replaced with the $EMAILENGINE_TOKEN placeholder the generated
    // samples read, rather than the token held for this tab. That one is usually a
    // throwaway minted for the reference page, so pasting it into a snippet produces a
    // command that stops working within the hour - and a live credential should not be
    // the thing that ends up in a ticket or a chat message.
    const curlForRequest = request => {
        const lines = [
            `curl -X ${request.method} ${shellQuote(window.location.origin + request.url)}`,
            // double quotes, so the shell expands the variable
            `${INDENT}-H "Authorization: Bearer $${TOKEN_ENV_VAR}"`
        ];

        for (const [name, value] of Object.entries(request.headers)) {
            if (name !== 'Authorization') {
                lines.push(`${INDENT}-H ${shellQuote(`${name}: ${value}`)}`);
            }
        }

        if (request.body) {
            lines.push(`${INDENT}-d ${shellQuote(request.body)}`);
        }

        return lines.join(' \\\n');
    };

    // Both entry points below - send and copy-as-curl - read the same form and report the
    // same validation failures in the same place, so they share the preamble. Returns null
    // when the form is not ready to be turned into a request, having said why.
    const prepareRequest = form => {
        const status = form.querySelector('.ee-ref-try-status');
        status.textContent = '';

        try {
            return buildRequest(form);
        } catch (err) {
            status.textContent = err.message;
            return null;
        }
    };

    // One delegated listener for every try-it form on the page, matching how
    // static/js/ui.js handles the copy buttons.
    const initTryIt = () => {
        document.addEventListener('click', event => {
            const button = event.target.closest('.ee-ref-try-curl');
            if (!button) {
                return;
            }

            const request = prepareRequest(button.closest('.ee-ref-try'));
            if (request) {
                window.uiCopyText(curlForRequest(request), button);
            }
        });

        document.addEventListener('submit', async event => {
            const form = event.target.closest('.ee-ref-try');
            if (!form) {
                return;
            }

            event.preventDefault();

            const request = prepareRequest(form);
            if (!request) {
                return;
            }

            const status = form.querySelector('.ee-ref-try-status');
            const button = form.querySelector('button[type="submit"]');

            window.uiButtonBusy(button, true);
            const started = performance.now();

            try {
                const response = await fetch(request.url, {
                    method: request.method,
                    headers: request.headers,
                    body: request.body
                });
                await renderResponse(form, response, Math.round(performance.now() - started));
            } catch (err) {
                status.textContent = `Request failed: ${err.message}`;
            } finally {
                window.uiButtonBusy(button, false);
            }
        });
    };

    // Feedback line on the access-token page; elsewhere (the "no token set" banner) there
    // is no such element and a toast carries the message instead.
    const say = (message, ok) => {
        const feedback = document.getElementById('ref-token-feedback');
        if (feedback) {
            feedback.textContent = message;
            feedback.className = ok ? 'text-success text-sm' : 'text-base-content/70 text-sm';
            return;
        }
        window.showToast(message, ok ? 'check-circle' : 'alert-triangle');
    };

    const revokeMinted = async token => {
        try {
            await window.uiPostJson('/admin/reference/token/revoke', { token });
            return true;
        } catch (err) {
            return false;
        }
    };

    const activate = async (token, expires, message) => {
        // Replacing a minted token would otherwise leave it working in Redis for the rest of
        // its hour with nothing pointing at it
        const previous = tokenStore.read();
        if (previous && previous.expires && previous.token !== token) {
            await revokeMinted(previous.token);
        }

        tokenStore.write(token, expires);
        const field = document.getElementById('ref-access-token');
        if (field) {
            field.value = '';
        }
        paintTokenStatus();
        say(message, true);
    };

    // Minting is reachable from the access-token page AND from the banner on every other
    // reference page, so it is bound by class through one delegated listener rather than
    // by id on a single button.
    const initMint = () => {
        document.addEventListener('click', async event => {
            const btn = event.target.closest('.ref-token-mint');
            if (!btn) {
                return;
            }

            event.preventDefault();
            window.uiButtonBusy(btn, true);

            try {
                const data = await window.uiPostJson('/admin/reference/token');
                if (!data || !data.success) {
                    throw new Error((data && data.message) || 'Request failed');
                }
                await activate(data.token, data.expires, `Temporary token minted, valid for ${minutesLeft(data.expires)} minutes.`);
            } catch (err) {
                say(`Could not mint a token: ${err.message}`, false);
            } finally {
                window.uiButtonBusy(btn, false);
            }
        });
    };

    // The paste/clear controls exist only on the access-token page.
    const initTokenForm = () => {
        const field = document.getElementById('ref-access-token');
        if (!field) {
            return;
        }

        // Reflect what is already held for this tab
        const existing = tokenStore.read();
        if (existing) {
            say(existing.expires ? `A temporary token is active, ${minutesLeft(existing.expires)} minutes left.` : 'A token is active.', true);
        }

        document.getElementById('ref-token-set').addEventListener('click', () => {
            const token = field.value.trim();
            if (!token) {
                say('Paste a token first.', false);
                return;
            }
            activate(token, null, 'Token set for this tab.').catch(err => say(err.message, false));
        });

        document.getElementById('ref-token-clear').addEventListener('click', async () => {
            const entry = tokenStore.read();

            // Drop it locally first, so the field is cleared even if the revoke call fails
            tokenStore.clear();
            field.value = '';
            paintTokenStatus();

            // A token this page minted is deleted for real rather than left working in
            // Redis until it expires. A pasted token belongs to the user - only forget it.
            if (!entry || !entry.expires) {
                say('Token cleared.', false);
                return;
            }

            say((await revokeMinted(entry.token)) ? 'Temporary token cleared and revoked.' : 'Token cleared here, but revoking it on the server failed.', false);
        });
    };

    document.addEventListener('DOMContentLoaded', () => {
        initHighlighting();
        initFilter();
        initSampleTabs();
        initTryIt();
        initMint();
        initTokenForm();
        paintTokenStatus();

        // On load rather than here: a target inside an inactive response tab needs the tab
        // switched, which needs FlyonUI
        whenComponentsReady(revealTarget);
    });

    // Same-page property links only change the fragment, so the load-time pass does not
    // run for them
    window.addEventListener('hashchange', revealTarget);
})();
