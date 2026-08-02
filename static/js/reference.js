'use strict';

// Client behavior for the server-rendered API reference (/admin/reference).
//
// The page arrives as finished HTML - operations, schemas, examples and code samples
// are all rendered by lib/api-reference/ on the server. Nothing here builds page
// content; this file only adds the three things that need a browser: deferred syntax
// highlighting, the sidebar filter, and the try-it request runner.

(() => {
    // Responses larger than this are truncated before being inserted into the DOM.
    // A message export or a full settings dump can be megabytes, and highlighting
    // that much text locks up the tab.
    const MAX_RESPONSE_CHARS = 200000;

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

    // Sidebar filter. Every operation is already in the DOM (hidden until the box has
    // input), so narrowing the list is plain matching - there is no index to fetch.
    const initFilter = () => {
        const input = document.getElementById('ref-filter');
        const results = document.getElementById('ref-filter-results');
        const tagList = document.getElementById('ref-tag-list');
        const empty = document.getElementById('ref-filter-empty');

        if (!input || !results || !tagList) {
            return;
        }

        const hits = Array.from(results.querySelectorAll('.ee-ref-hit')).map(el => ({
            el,
            text: (el.dataset.search || '').toLowerCase()
        }));

        input.addEventListener('input', () => {
            const terms = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);

            if (!terms.length) {
                results.classList.add('hidden');
                tagList.classList.remove('hidden');
                return;
            }

            tagList.classList.add('hidden');
            results.classList.remove('hidden');

            let visible = 0;
            for (const hit of hits) {
                const match = terms.every(term => hit.text.includes(term));
                hit.el.classList.toggle('hidden', !match);
                if (match) {
                    visible++;
                }
            }

            empty.classList.toggle('hidden', visible > 0);
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

    // One delegated listener for every try-it form on the page, matching how
    // static/js/ui.js handles the copy buttons.
    const initTryIt = () => {
        document.addEventListener('submit', async event => {
            const form = event.target.closest('.ee-ref-try');
            if (!form) {
                return;
            }

            event.preventDefault();

            const status = form.querySelector('.ee-ref-try-status');
            const button = form.querySelector('button[type="submit"]');
            status.textContent = '';

            let request;
            try {
                request = buildRequest(form);
            } catch (err) {
                status.textContent = err.message;
                return;
            }

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
        initTryIt();
        initMint();
        initTokenForm();
        paintTokenStatus();
    });
})();
