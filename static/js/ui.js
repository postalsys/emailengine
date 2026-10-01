/* global document, window, navigator, localStorage, fetch, Event, KeyboardEvent, AbortController, HSStaticMethods, HSOverlay */

'use strict';

/*
 * Shared UI behaviors for the Tailwind v4 + FlyonUI admin theme. Backs the
 * central component library in views/partials/ui/ - page scripts use these
 * helpers instead of re-implementing them per page.
 */

// Fade an element out (expects a transition-opacity class on it) and remove it
window.uiDismissFade = elm => {
    elm.classList.add('opacity-0');
    window.setTimeout(() => elm.remove(), 300);
};

// Toast notifications. Same signature as the legacy implementation so the
// existing showToast(message, icon) call sites keep working; icon is a
// legacy icon name mapped to an iconify class below (default: info).
const TOAST_ICONS = {
    'alert-triangle': 'icon-[tabler--alert-triangle] text-error',
    'check-circle': 'icon-[tabler--circle-check] text-success',
    info: 'icon-[tabler--info-circle] text-info'
};

window.showToast = (message, icon) => {
    let container = document.getElementById('toastContainer');
    if (!container) {
        return;
    }

    let toast = document.createElement('div');
    toast.className = 'alert alert-soft flex items-start gap-3 shadow-lg mb-2 transition-opacity duration-300';
    toast.setAttribute('role', 'alert');

    let iconElm = document.createElement('span');
    iconElm.className = `${TOAST_ICONS[icon] || TOAST_ICONS.info} size-6 shrink-0`;
    toast.appendChild(iconElm);

    let contentElm = document.createElement('div');
    contentElm.className = 'grow';

    let titleElm = document.createElement('strong');
    titleElm.className = 'block';
    titleElm.textContent = 'EmailEngine';
    contentElm.appendChild(titleElm);

    let bodyElm = document.createElement('div');
    bodyElm.textContent = message;
    contentElm.appendChild(bodyElm);

    toast.appendChild(contentElm);

    let removeToast = () => window.uiDismissFade(toast);

    let closeElm = document.createElement('button');
    closeElm.type = 'button';
    closeElm.className = 'shrink-0 opacity-50 hover:opacity-100 text-xl leading-none';
    closeElm.setAttribute('aria-label', 'Close');
    closeElm.innerHTML = '&times;';
    closeElm.addEventListener('click', removeToast);
    toast.appendChild(closeElm);

    container.appendChild(toast);
    window.setTimeout(removeToast, 5000);
};

// Modal helpers for converted views (FlyonUI overlay component)
window.uiModal = {
    open(target) {
        if (typeof HSOverlay !== 'undefined') {
            HSOverlay.open(typeof target === 'string' ? document.querySelector(target) : target);
        }
    },
    close(target) {
        if (typeof HSOverlay !== 'undefined') {
            HSOverlay.close(typeof target === 'string' ? document.querySelector(target) : target);
        }
    }
};

// FlyonUI picks the component that handles a keypress from the event target, and a tab strip
// reports itself as opened while defining no Escape handler - so it swallows the key instead of
// letting it reach the dialog around it, and a modal containing tabs stops closing on Escape the
// moment the reader switches tab, while every other modal in the app still closes. Re-aim the key
// at the dialog rather than closing it here: HSOverlay defers parts of its close to timers and to
// transitionend, and driving it from outside strands the dialog (see the note on uiConfirm below).
// Capture phase, so this runs before the strip sees the event. The re-dispatched event targets the
// modal, which matches no [data-tab], so it cannot come back round.
document.addEventListener(
    'keydown',
    e => {
        if (e.key !== 'Escape' || !e.target || !e.target.closest) {
            return;
        }
        let tab = e.target.closest('[data-tab]');
        let modal = tab && tab.closest('.modal.open');
        if (modal) {
            modal.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
        }
    },
    true
);

// Promise-returning confirmation over a ui/modal. Resolves true only when the element matching
// `okSelector` was clicked before the dialog closed; every other way out - Cancel, the corner
// close, Escape, a backdrop click - resolves false, which is the safe answer for a
// confirmation. A dialog that is not on the page resolves false for the same reason: not
// running is recoverable, acting without being asked is not.
//
// Every button in the dialog must dismiss it through data-overlay, which is FlyonUI's own
// path. Nothing here closes the overlay, and callers must not either: HSOverlay defers parts
// of both open and close to timers and to transitionend, so a close driven from outside races
// with itself. One begun in the 50ms before `opened` is set is simply undone, and one begun
// mid-transition never re-adds `hidden` - either way the dialog is stranded on screen with no
// way out, which on a confirmation is the worst failure available.
//
// Callers fill in their own text first; only the answer is shared.
window.uiConfirmModal = (target, okSelector) => {
    const modal = typeof target === 'string' ? document.querySelector(target) : target;
    const ok = modal && modal.querySelector(okSelector);
    if (!ok) {
        return Promise.resolve(false);
    }

    return new Promise(resolve => {
        let confirmed = false;
        const onConfirm = () => {
            confirmed = true;
        };

        // Removed by hand rather than with {once:true}: a dismissal leaves it attached, and
        // one per call would accumulate on DOM that outlives the promise
        ok.addEventListener('click', onConfirm);
        modal.addEventListener(
            'close.overlay',
            () => {
                ok.removeEventListener('click', onConfirm);
                resolve(confirmed);
            },
            { once: true }
        );

        window.uiModal.open(modal);
    });
};

// Re-initialize FlyonUI components inside dynamically injected markup
window.uiAutoInit = () => {
    if (typeof HSStaticMethods !== 'undefined' && typeof HSStaticMethods.autoInit === 'function') {
        HSStaticMethods.autoInit();
    }
};

// Light/dark theme handling. The effective theme is stored in localStorage
// ("eeTheme"); when unset, the CSS falls back to prefers-color-scheme (the
// dark theme is registered with prefersdark). A small inline script in the
// layout <head> applies the stored value before first paint to avoid a flash.
(function () {
    function storedTheme() {
        try {
            return localStorage.getItem('eeTheme');
        } catch (err) {
            return null;
        }
    }

    function effectiveTheme() {
        let stored = storedTheme();
        if (stored === 'light' || stored === 'dark') {
            return stored;
        }
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function updateToggleIcons() {
        let theme = effectiveTheme();
        for (let elm of document.querySelectorAll('.theme-toggle-light')) {
            elm.classList.toggle('hidden', theme !== 'dark');
        }
        for (let elm of document.querySelectorAll('.theme-toggle-dark')) {
            elm.classList.toggle('hidden', theme === 'dark');
        }
    }

    // resolved light/dark choice for embeds that follow the admin theme
    // (e.g. the ee-client message browser)
    window.uiEffectiveTheme = effectiveTheme;

    window.uiToggleTheme = () => {
        let next = effectiveTheme() === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        try {
            localStorage.setItem('eeTheme', next);
        } catch (err) {
            // private mode - theme just will not persist
        }
        updateToggleIcons();
    };

    // Run fn whenever the effective light/dark theme may have changed: the topbar
    // toggle rewrites data-theme on the root element, and with no stored choice
    // the effective theme follows the system scheme. Used by embeds that cannot
    // follow the theme through CSS alone (ACE editors, the message browser).
    window.uiOnThemeChange = fn => {
        new MutationObserver(() => fn()).observe(document.documentElement, { attributeFilter: ['data-theme'] });
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => fn());
    };

    // keep the sun/moon toggle icons in sync when the system scheme flips
    // while no explicit theme is stored (the toggle click path already updates
    // them directly; the extra run is idempotent)
    window.uiOnThemeChange(updateToggleIcons);

    document.addEventListener('DOMContentLoaded', () => {
        for (let btn of document.querySelectorAll('.theme-toggle-btn')) {
            btn.addEventListener('click', e => {
                e.preventDefault();
                window.uiToggleTheme();
            });
        }
        updateToggleIcons();
    });
})();

// Native <datalist> autocomplete: creates a datalist with the given id and
// option values, appends it to the body and points the given inputs at it
// (replaces the old bootstrap-autocomplete plugin)
window.uiDatalist = (id, values, inputs) => {
    let listElm = document.createElement('datalist');
    listElm.id = id;
    for (let value of values) {
        let optionElm = document.createElement('option');
        optionElm.value = value;
        listElm.appendChild(optionElm);
    }
    document.body.appendChild(listElm);
    for (let inputElm of inputs || []) {
        inputElm.setAttribute('list', id);
    }
};

// Fullscreen toggle for ACE editor blocks: binds every .toggle-fullscreen
// link whose data-target names an editor in the passed Map (element id ->
// ace instance). Clicking toggles .full-screen-div on the editor container;
// Escape or the layout's floating #fullscreen-close-btn exits. The editor is
// resized and refocused on both transitions.
window.uiEditorFullscreen = editors => {
    // floating exit button from the layout: Escape has no key on touch devices.
    // The fullscreen editor is derived from the DOM instead of tracked state, so
    // pages that call uiEditorFullscreen more than once (e.g. config/ai) stay
    // correct: only the listener whose editors Map owns the element acts.
    const closeBtn = document.getElementById('fullscreen-close-btn');

    const setFullscreen = (targetElm, editor, on) => {
        targetElm.classList.toggle('full-screen-div', on);
        if (closeBtn) {
            closeBtn.classList.toggle('hidden', !on);
        }
        editor.resize();
        editor.focus();
    };

    if (closeBtn) {
        closeBtn.addEventListener('click', e => {
            e.preventDefault();
            let targetElm = document.querySelector('.full-screen-div');
            if (targetElm && editors.has(targetElm.id)) {
                setFullscreen(targetElm, editors.get(targetElm.id), false);
            }
        });
    }

    for (let toggleElm of document.querySelectorAll('.toggle-fullscreen')) {
        let target = toggleElm.dataset.target;
        if (!editors.has(target)) {
            continue;
        }
        let targetElm = document.getElementById(target);
        let editor = editors.get(target);

        toggleElm.addEventListener('click', e => {
            e.preventDefault();
            e.stopPropagation();
            setFullscreen(targetElm, editor, !targetElm.classList.contains('full-screen-div'));
        });

        targetElm.addEventListener('keydown', e => {
            if (e.key === 'Escape' && targetElm.classList.contains('full-screen-div')) {
                setFullscreen(targetElm, editor, false);
            }
        });
    }
};

// Keyboard hints that spell a modifier differently on macOS (ui/search-input
// renders `shortcut` with an optional `shortcutMac`). The server cannot know
// the platform, so it emits the Ctrl form and the Mac spelling rides along in
// data-mac; this swaps it in. Generic on purpose - the next page that binds a
// hotkey gets the right label without reaching into the partial's markup.
document.addEventListener('DOMContentLoaded', () => {
    if (!/mac/i.test((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '')) {
        return;
    }

    for (let elm of document.querySelectorAll('kbd[data-mac]')) {
        elm.textContent = elm.dataset.mac;
    }
});

// Writes a string to the clipboard and confirms it on the button that asked
// for it (the copy icon flips to a checkmark, a failure raises a toast).
// Uses the async Clipboard API where available; self-hosted installs served
// over plain HTTP are not a secure context, so those fall back to execCommand
// on a throwaway textarea (a selection on the source element itself would not
// work for password inputs or ACE editors, which only render the visible
// lines).
//
// Exposed rather than kept inside the delegated handler below because not
// every copyable value can be pointed at: the API reference's copy-as-curl
// serializes its try-it form at click time, so there is no element holding the
// text and no data attribute it could have been rendered into.
window.uiCopyText = (value, btn) => {
    let copied;
    if (navigator.clipboard && window.isSecureContext) {
        copied = navigator.clipboard.writeText(value).then(
            () => true,
            () => false
        );
    } else {
        let helper = document.createElement('textarea');
        helper.value = value;
        helper.setAttribute('readonly', '');
        helper.style.position = 'fixed';
        helper.style.top = '-1000px';
        document.body.appendChild(helper);
        helper.select();
        let ok = false;
        try {
            ok = document.execCommand('copy');
        } catch (err) {
            ok = false;
        }
        helper.remove();
        copied = Promise.resolve(ok);
    }

    return copied.then(ok => {
        if (!ok) {
            window.showToast('Failed to copy to clipboard', 'alert-triangle');
            return false;
        }
        let icon = btn && btn.querySelector('[class*="icon-"]');
        if (icon && icon.classList.replace('icon-[tabler--copy]', 'icon-[tabler--check]')) {
            window.setTimeout(() => icon.classList.replace('icon-[tabler--check]', 'icon-[tabler--copy]'), 1500);
        }
        return true;
    });
};

// Copy-to-clipboard buttons: a .copy-btn with data-copy-target="#selector"
// copies the target's value (inputs), ACE editor content (a mounted
// ui/code-editor div) or text content. Delegated, so buttons inside
// dynamically injected markup work without re-binding.
document.addEventListener('click', e => {
    let btn = e.target.closest('.copy-btn');
    if (!btn) {
        return;
    }
    // toolbar copy controls are <a href="#"> links
    e.preventDefault();

    let value;
    if ('copyValue' in btn.dataset) {
        // literal value carried on the button itself (e.g. the per-row ids in
        // ui/entity-id) - no target element needed
        value = btn.dataset.copyValue;
    } else {
        let target = btn.dataset.copyTarget ? document.querySelector(btn.dataset.copyTarget) : null;
        if (!target) {
            return;
        }

        let aceEntry = uiAceInstances.get(target);
        if (aceEntry) {
            value = aceEntry.editor.getValue();
        } else {
            value = 'value' in target ? target.value : target.textContent;
        }
    }

    window.uiCopyText(value, btn);
});

// Cross-tab links: an element with data-goto-tab="<panel id>" activates that
// panel's tab in a ui/tabs strip. The target may sit inside another strip's
// panel (a nested method switch), so the whole ancestor chain of tabpanels is
// activated outermost-first - otherwise the target tab would light up inside
// a panel that stays hidden. Each panel names its own button through
// aria-labelledby (the ui/tabs contract, read the same way in reference.js)
// rather than this handler recomposing ui/tab's "<id>-tab" id convention.
// Delegated like the copy buttons, so pages need no script of their own for
// a "see the other tab" pointer.
document.addEventListener('click', e => {
    let link = e.target.closest('[data-goto-tab]');
    if (!link) {
        return;
    }

    let tabs = [];
    for (
        let panel = document.getElementById(link.dataset.gotoTab);
        panel;
        panel = panel.parentElement && panel.parentElement.closest('[role="tabpanel"]')
    ) {
        let tab = document.getElementById(panel.getAttribute('aria-labelledby'));
        if (tab) {
            tabs.unshift(tab);
        }
    }

    for (let tab of tabs) {
        tab.click();
    }
});

// Resource-list row delete: a .list-delete-btn (rendered by ui/row-actions in
// a kebab menu) opens the page's shared confirm modal, filling in the resource
// name and either the modal form's hidden id field (payload-based delete
// routes such as /admin/webhooks/delete) or the form action (path-param delete
// routes such as /admin/gateways/delete/{id}). Delegated, so it covers every
// list page without per-page wiring.
document.addEventListener('click', e => {
    let btn = e.target.closest('.list-delete-btn');
    if (!btn) {
        return;
    }
    e.preventDefault();

    let modalSel = btn.dataset.deleteModal;
    let modal = modalSel ? document.querySelector(modalSel) : null;
    if (!modal) {
        return;
    }

    let nameEl = modal.querySelector('.delete-target-name');
    if (nameEl) {
        nameEl.textContent = btn.dataset.deleteName || '';
    }

    let form = modal.querySelector('form');
    if (form) {
        if (btn.dataset.deleteAction) {
            // path-param delete routes carry the id in the URL
            form.setAttribute('action', btn.dataset.deleteAction);
        }
        // payload-based delete routes fill the hidden id field (ui/delete-modal
        // tags it with .delete-target-id)
        let field = form.querySelector('.delete-target-id');
        if (field) {
            field.value = btn.dataset.deleteId || '';
        }
    }

    window.uiModal.open(modalSel);
});

// Server-side flash messages (views/partials/alerts.hbs): close button plus
// auto-dismiss after 15 seconds
document.addEventListener('DOMContentLoaded', () => {
    let alerts = document.querySelectorAll('.flash-alert');
    if (!alerts.length) {
        return;
    }

    for (let alert of alerts) {
        let closeBtn = alert.querySelector('.flash-alert-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => window.uiDismissFade(alert));
        }
    }

    window.setTimeout(() => {
        for (let alert of document.querySelectorAll('.flash-alert')) {
            window.uiDismissFade(alert);
        }
    }, 15 * 1000);
});

// POST a JSON payload to an admin endpoint with the page CSRF crumb included.
// Throws on HTTP errors; returns the parsed response body.
window.uiPostJson = async (url, payload) => {
    const res = await fetch(url, {
        method: 'post',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(Object.assign({ crumb: document.getElementById('crumb').value }, payload))
    });
    if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
    }
    return await res.json();
};

// Report the outcome of an admin JSON action as a toast. These endpoints answer
// with {success, error, statusCode}, and every caller used to spell out the same
// three-way ternary, which is why a failing endpoint named the HTTP status it got
// on one page and not on the next.
window.uiToastResult = (data, okMessage, failMessage) => {
    if (data.success) {
        window.showToast(okMessage, 'check-circle');
        return;
    }
    const status = data.statusCode ? `HTTP ${data.statusCode}: ` : '';
    window.showToast(data.error ? status + data.error : failMessage, 'alert-triangle');
};

// Toggle an async action button's busy state: make the control unclickable and
// swap its icon span to a spinner while busy, restoring it after. Works on both
// <button> (disabled) and the action links in dropdown menus (<a> takes no
// disabled attribute, so it gets aria-disabled plus the pointer-events class).
// A control rendered without a leading icon gets a spinner span for the
// duration - the busy state has to be visible on those too.
window.uiButtonBusy = (btn, busy) => {
    if (btn.tagName === 'A') {
        btn.classList.toggle('pointer-events-none', !!busy);
        btn.classList.toggle('opacity-60', !!busy);
        if (busy) {
            btn.setAttribute('aria-disabled', 'true');
        } else if (!btn.classList.contains('dropdown-disabled')) {
            // The reset owns the busy window, not the control's own state: an action that
            // switches its entry off for good (clearing an account's stored logs empties the
            // download and clear entries) keeps the disabled marker it just set.
            btn.removeAttribute('aria-disabled');
        }
    } else {
        btn.disabled = !!busy;
    }

    if (btn.tagName === 'INPUT') {
        // void element - nothing to put a spinner inside
        return;
    }

    let icon = btn.querySelector('[class*="icon-["]');
    if (!icon) {
        if (!busy) {
            return;
        }
        icon = document.createElement('span');
        icon.className = 'size-4 shrink-0';
        icon.dataset.busySpinner = 'true';
        btn.prepend(icon);
    }

    if (busy) {
        if (!('idleIcon' in icon.dataset)) {
            icon.dataset.idleIcon = Array.from(icon.classList).find(c => c.startsWith('icon-[')) || '';
        }
        if (icon.dataset.idleIcon) {
            icon.classList.remove(icon.dataset.idleIcon);
        }
        icon.classList.add('icon-[tabler--loader-2]', 'animate-spin');
    } else if (icon.dataset.busySpinner) {
        icon.remove();
    } else {
        icon.classList.remove('icon-[tabler--loader-2]', 'animate-spin');
        if (icon.dataset.idleIcon) {
            icon.classList.add(icon.dataset.idleIcon);
        }
    }
};

/*
 * Double-submit guard for the admin POST forms.
 *
 * A plain form POST gives no feedback while it is in flight, and the actions
 * behind these forms are slow in the ways an operator cannot see: they talk to
 * a mail server, an OAuth provider or the license server, or they rewrite a lot
 * of Redis. Without feedback the button gets clicked again, and the second
 * request either duplicates the work (a second account, a second delete) or
 * loses a race against a single-use nonce and reports an error for an operation
 * that actually succeeded. So the first submit latches the form: later submits
 * are cancelled, and the button that was pressed spins until the navigation
 * lands.
 *
 * Global rather than opt-in per form (it replaces a `pending-form` class that
 * three forms out of forty carried): on this surface a POST that takes a while
 * is the normal case, and a page that wants to own its submission cancels the
 * event - which is exactly what the listener skips on.
 */
const uiFormBusy = new Map();

// Bubble phase on document, so every listener the form itself installed has
// already run and event.defaultPrevented tells us whether the page took over.
// (A page that delegates from `document` instead registers after this file and
// so is not seen - the API reference's "Try it" forms do that, and stay clear of
// this guard by not being POST forms.)
document.addEventListener('submit', event => {
    const form = event.target;
    // Attributes rather than properties throughout: a form control named `method` or `target`
    // shadows the same-named property on HTMLFormElement, and this handler runs on every form.
    if (event.defaultPrevented || !form || (form.getAttribute('method') || 'get').toLowerCase() !== 'post') {
        return;
    }

    // A form aimed at another browsing context leaves this page in place, so
    // there is no navigation to end the busy state and nothing to latch.
    //
    // Read the attribute, not the property: a form control named `target` shadows
    // HTMLFormElement.target, so form.target can be an <input> element. That threw here and took
    // every busy button on the page down with it.
    const target = (form.getAttribute('target') || '').trim().toLowerCase();
    if (target && target !== '_self') {
        return;
    }

    if (uiFormBusy.has(form)) {
        // Already submitted once. Covers implicit submission (Enter in a text
        // field), which a disabled default button does not always stop.
        event.preventDefault();
        return;
    }

    const submitter = event.submitter;
    // Static NodeList, so it stays usable as the record of what to re-enable.
    // input[type="submit"] is not used on the admin pages today; it is in the
    // selector because this guard applies to whatever form a page adds next.
    const buttons = form.querySelectorAll('button[type="submit"], button:not([type]), input[type="submit"]');
    let submitterField = null;

    // The form data set is built AFTER this event and skips disabled controls,
    // the submitter included - so disabling it would stop its name/value from
    // posting, and that value is what picks the branch the server takes (the
    // MCP consent page posts its decision that way). Move it into a hidden
    // input first.
    if (submitter && submitter.name) {
        submitterField = document.createElement('input');
        submitterField.type = 'hidden';
        submitterField.name = submitter.name;
        submitterField.value = submitter.value;
        form.appendChild(submitterField);
    }

    uiFormBusy.set(form, { buttons, submitter, submitterField });

    for (const btn of buttons) {
        // A browser that reports no event.submitter leaves us unable to tell which button was
        // pressed, and disabling one that carries a name would drop the value the server branches
        // on - so those keep working and the latch alone does the guarding.
        if (btn === submitter || (!submitter && btn.name)) {
            continue;
        }
        btn.disabled = true;
    }
    if (submitter) {
        window.uiButtonBusy(submitter, true);
    }
});

// Back from a submitted form: the bfcache restores the page with the latch
// still set and the buttons still disabled, which would leave the form dead.
// (An aborted submit - Esc or Stop while the page stays - is deliberately not
// recovered: a reload fixes it, and a timer that guessed wrong would re-arm the
// buttons underneath a request that is still running.)
window.addEventListener('pageshow', event => {
    if (!event.persisted) {
        return;
    }
    for (const state of uiFormBusy.values()) {
        if (state.submitterField) {
            state.submitterField.remove();
        }
        for (const btn of state.buttons) {
            if (btn === state.submitter) {
                window.uiButtonBusy(btn, false);
            } else {
                btn.disabled = false;
            }
        }
    }
    uiFormBusy.clear();
});

// Run an async action from a button, with the button busy for its duration.
// The busy button is the re-entrancy guard, so the action cannot be started
// twice, and the reset runs however the action ends - the shape every action
// button that posts with fetch() needs, and the one that used to be spelled
// out (and occasionally forgotten) per page. `run` returns a promise; a
// rejection it does not handle itself is reported as a toast.
window.uiBusyAction = (btn, run) => {
    if (btn.disabled || btn.getAttribute('aria-disabled') === 'true') {
        return;
    }
    window.uiButtonBusy(btn, true);
    Promise.resolve()
        .then(run)
        .catch(err => window.showToast('Request failed\n' + err.message, 'alert-triangle'))
        .finally(() => window.uiButtonBusy(btn, false));
};

// ACE editor theming: light and dark variants per editor kind, applied on
// creation and re-applied whenever the admin theme changes. The theme files
// must exist under static/js/ace/ - they are copied from ace-builds by
// copy-static-files.sh and ship in the pkg binary via the static/**/* asset glob.
// Their stylesheets are linked by views/partials/ace_assets.hbs, which also puts
// ACE in strict-CSP mode so it injects none of its own.
const uiAceThemes = {
    editor: { light: 'ace/theme/xcode', dark: 'ace/theme/tomorrow_night' },
    preview: { light: 'ace/theme/kuroir', dark: 'ace/theme/tomorrow_night_eighties' }
};

// ACE keeps its stylesheets inside its JavaScript and injects them as elements the admin
// Content-Security-Policy refuses (it accepts a stylesheet only with the request nonce, which
// ACE cannot set). Strict mode stops the injection and the sheets are linked instead:
// views/partials/ace_assets.hbs carries them in the markup for the pages that always have an
// editor, and this adds whatever is missing for the one that loads ACE lazily from script (the
// try-it panels in static/js/reference.js). Both paths reach ACE through the two helpers below,
// so this is the one place that has to know. The hrefs come from uiAceThemes, so a theme added
// there needs no second edit.
const uiAceEnsureAssets = () => {
    ace.config.set('useStrictCSP', true);

    let sheets = ['/static/js/ace/css/ace.css'];
    for (let kind of Object.values(uiAceThemes)) {
        for (let theme of Object.values(kind)) {
            sheets.push(`/static/js/ace/css/theme/${theme.split('/').pop()}.css`);
        }
    }

    for (let href of sheets) {
        if (!document.querySelector(`link[href="${href}"]`)) {
            let link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = href;
            document.head.appendChild(link);
        }
    }
};

// container element -> { editor, kind }; also the lookup the .copy-btn
// handler uses to read the full session value of a targeted editor
const uiAceInstances = new Map();

const uiAceApplyTheme = entry => entry.editor.setTheme(uiAceThemes[entry.kind][window.uiEffectiveTheme()]);

const uiAceRegister = (editor, kind) => {
    const entry = { editor, kind };
    uiAceInstances.set(editor.container, entry);
    uiAceApplyTheme(entry);
    if (uiAceInstances.size === 1) {
        window.uiOnThemeChange(() => uiAceInstances.forEach(uiAceApplyTheme));
    }
    return editor;
};

// ACE editor bootstrap: theme following the admin theme, the given mode, and
// the initial value loaded into the session. Extra ace options pass through
// via opts.
window.uiAceEditor = (id, mode, value, opts) => {
    uiAceEnsureAssets();
    const editor = opts ? ace.edit(id, opts) : ace.edit(id);
    uiAceRegister(editor, 'editor');
    editor.session.setMode(`ace/mode/${mode}`);
    if (value !== undefined) {
        editor.session.setValue(value);
    }
    return editor;
};

// Read-only preview pane variant: gutter, no print margin or active-line
// highlight, with its own theme pair to keep previews visually distinct
window.uiAcePreview = (id, mode, opts) => {
    uiAceEnsureAssets();
    const editor = ace.edit(id, Object.assign({ showGutter: true }, opts));
    editor.setReadOnly(true);
    editor.setShowPrintMargin(false);
    editor.setHighlightActiveLine(false);
    uiAceRegister(editor, 'preview');
    editor.session.setMode(`ace/mode/${mode}`);
    return editor;
};

// Client code-example engine for the server-config pages (config/smtp,
// config/imap-proxy): renders each code template with live form values
// substituted, highlights it via hljs, and re-renders whenever a
// .trigger-example-render control changes. Returns the render function so page
// scripts (e.g. the TLS provisioning error path) can re-render on demand.
// config = {
//   header:           comment block prepended to every example
//   portField:        id of the port input backing the PORT placeholder
//   passwordField:    id of the password input backing the PASSWORD placeholder
//   passwordFallback: placeholder shown while no password is configured
//   authField:        id of a checkbox choosing codeAuth/codeNoAuth (optional;
//                     without it codeAuth is always used)
//   replacements:     extra { PLACEHOLDER: () => value } substitutions
//   templates:        { key: { lang, target, codeAuth, codeNoAuth } }
// }
window.uiCodeExamples = config => {
    const value = id => document.getElementById(id).value;
    const checked = id => document.getElementById(id).checked;

    const renderTemplate = template => {
        const useAuth = !config.authField || checked(config.authField);

        const password = !value(config.passwordField)
            ? config.passwordFallback
            : checked('exampleShowPassword')
              ? value(config.passwordField)
              : '******';

        let code = (config.header + (useAuth ? template.codeAuth : template.codeNoAuth))
            .replace(/HOST/g, window.location.hostname)
            .replace(/PORT/g, Number(value(config.portField)) || 0)
            .replace(/USERNAME/g, 'account_id')
            .replace(/PASSWORD/g, password);

        for (const [placeholder, resolve] of Object.entries(config.replacements || {})) {
            code = code.replace(new RegExp(placeholder, 'g'), resolve());
        }

        return hljs.highlight(code, { language: template.lang }).value;
    };

    const renderExamples = () => {
        for (const template of Object.values(config.templates)) {
            document.getElementById(template.target).innerHTML = renderTemplate(template);
        }

        document.getElementById('exampleShowPassword').disabled = (config.authField && !checked(config.authField)) || !value(config.passwordField);
    };

    for (const elm of document.querySelectorAll('.trigger-example-render')) {
        elm.addEventListener('change', renderExamples);
    }

    renderExamples();
    return renderExamples;
};


// The MCP tool count: how many of the endpoint's tools a credential would actually be offered.
//
// Shared by the three places an MCP token is minted - the access-token form, the MCP config page's
// generator and the OAuth consent prompt - because all three ask the same question, and the count
// is the one thing a permission record does not tell a reader: a record that looks generous can
// still leave an agent holding one tool.
//
// Three filters, the same three lib/mcp/tools.js toolVisibleTo() applies to tools/list: the scopes
// (a tool is offered only through a surface scope whose table covers it), the permission record,
// and the account binding - a credential bound to one account is never offered the tools that take
// no account argument, because there is nothing to bind them to. This is the browser's copy of
// that rule, and test/mcp-tools-test.js asserts the two agree over the whole catalog.
//
// `record` is { surfaces, grants | actions + groups, unrestricted, account }. `surfaces` lists the
// MCP scopes the token holds (absent: no scope bound). `grants` is a list of {action, group} pairs,
// the pair-list form; `actions` and `groups` are the two-axis form. `unrestricted` is the absence
// of a permissions record, which is a different answer from an empty one: the scopes are the only
// bound. A null record clears the element - the question does not apply to this credential at
// all, which is not the same as it having no tools.

// Whether a record allows one (action, group) pair, in whichever form it is written. The one
// reading of the record shape in the browser: the count and the token form's scope warning both
// ask this.
window.uiMcpRecordAllows = (record, action, group) => {
    if (record.unrestricted) {
        return true;
    }
    if (record.grants) {
        return record.grants.some(grant => grant.action === action && grant.group === group);
    }
    return record.actions.includes(action) && record.groups.includes(group);
};

window.uiMcpToolCount = (elm, record) => {
    // Parsed once per element: the account field repaints this per keystroke
    if (!elm.mcpTools) {
        elm.mcpTools = JSON.parse(elm.dataset.mcpTools || '[]');
    }
    let tools = elm.mcpTools;

    elm.replaceChildren();
    if (!tools.length || !record) {
        return;
    }

    let bound = !!(record.account || '').trim();
    let reachable = record.surfaces ? tools.filter(tool => (tool.surfaces || []).some(scope => record.surfaces.includes(scope))) : tools;
    let offered = bound ? reachable.filter(tool => tool.accountScoped) : reachable;
    let available = offered.filter(tool => window.uiMcpRecordAllows(record, tool.action, tool.group));

    let count = document.createElement('div');
    let countLabel = document.createElement('strong');
    countLabel.textContent = available.length + ' of ' + offered.length + ' MCP tools available';
    count.append(countLabel);
    elm.append(count);

    let names = document.createElement('div');
    names.className = 'text-base-content/60 break-words';
    names.textContent = available.length ? available.map(tool => tool.name).join(', ') : 'A connected agent would see no tools at all.';
    elm.append(names);

    // Said out loud rather than left as a smaller total: the tools a binding takes away are the
    // ones an agent would otherwise use to discover what it is connected to.
    let instanceWide = reachable.filter(tool => !tool.accountScoped);
    if (bound && instanceWide.length) {
        let note = document.createElement('div');
        note.className = 'text-base-content/60';
        note.textContent = 'Bound to one account, so the instance-wide tools are not offered: ' + instanceWide.map(tool => tool.name).join(', ') + '.';
        elm.append(note);
    }
};

// The level a page has selected per section, read off the radio groups. Every page renders one
// radio group per section, named `<prefix><section key>` by the mcp_access_levels partial; a
// section with no radio checked (the token form leaves a section out entirely while its scope is
// unticked) is declined.
window.uiMcpLevelChoice = (sections, prefix) => {
    let choice = {};
    for (let key of Object.keys(sections)) {
        let radio = document.querySelector('input[name="' + (prefix || '') + key + '"]:checked');
        choice[key] = radio ? radio.value : 'none';
    }
    return choice;
};

// The record a choice of section levels mints, as the count reads it and as the mint posts it:
// the scopes of the sections that were not declined and the union of their pairs. The browser's
// copy of mcpGrantsFor() in lib/token-permission-view.js, over the same table.
window.uiMcpLevelRecord = (sections, choice) => {
    let surfaces = [];
    let grants = [];
    for (let key of Object.keys(sections)) {
        let level = sections[key].levels.find(entry => entry.value === choice[key]);
        if (!level) {
            // Declined, or a level the table does not know - which counts as nothing rather than
            // as everything, the same direction every other reader of this table fails in
            continue;
        }
        surfaces.push(sections[key].scope);
        for (let pair of level.pairs) {
            if (!grants.some(grant => grant.action === pair.action && grant.group === pair.group)) {
                grants.push({ action: pair.action, group: pair.group });
            }
        }
    }
    return { surfaces, grants, unrestricted: false };
};

// Auto-wiring for the pages whose whole answer is a level per section (the MCP config generator
// and the consent prompt): the count element carries the section table and the radio name prefix,
// and repaints whenever a level or the account binding changes. The access-token form drives its
// own count instead, because its custom option is a hand-built record rather than a level.
document.addEventListener('DOMContentLoaded', () => {
    for (let elm of document.querySelectorAll('[data-mcp-auto-wire]')) {
        let sections = JSON.parse(elm.dataset.mcpSections || '{}');
        let prefix = elm.dataset.mcpLevelPrefix || '';
        let accountElm = elm.dataset.mcpAccountId ? document.getElementById(elm.dataset.mcpAccountId) : null;

        let paint = () => {
            let record = window.uiMcpLevelRecord(sections, window.uiMcpLevelChoice(sections, prefix));
            record.account = accountElm ? accountElm.value : '';
            window.uiMcpToolCount(elm, record);
        };

        for (let key of Object.keys(sections)) {
            for (let radio of document.querySelectorAll('input[name="' + prefix + key + '"]')) {
                radio.addEventListener('change', paint);
            }
        }
        if (accountElm) {
            // Per keystroke, so what the binding costs is visible while the field is being filled
            // in rather than only after it loses focus
            accountElm.addEventListener('input', paint);
        }
        paint();
    }
});

// The pickers (views/partials/ui/picker.hbs): one control with two faces, a search box with
// suggestions and a card naming what was picked, over whatever a page needs chosen from. Two
// sources exist. The account picker asks the server as the person types, because the account
// set is unbounded and every row costs a listing; the model picker filters a list the page
// already holds, because a provider serves a hundred models at most.
//
// The posted value never stops being a plain id in the hidden input the partial renders, and
// every change to it fires `input` and `change` there - so a page that watches that field (the
// MCP tool count follows the account on all three pages that mint a token) needs no knowledge of
// this at all. Everything below is about which id is in that input, and nothing else reads it.
//
// Every row is built as DOM nodes with textContent - account names and addresses are attacker-set
// (a display name arrives from a provider), model names and notes arrive from an API, and these
// rows are rendered on an authenticated admin page, which is the worst place to hand one an
// innerHTML. The ee-account-picker-* classes are the one set of styles both pickers share.
const uiPickerLine = (className, text) => {
    const elm = document.createElement('div');
    elm.className = className;
    elm.textContent = text;
    return elm;
};

const uiPickerBadge = (text, className) => {
    const badge = document.createElement('span');
    badge.className = 'badge badge-sm ' + className;
    badge.textContent = text;
    return badge;
};

// The title line: the name a person recognises, plus a badge. Shared by the card and by a result
// row, which differ only in the weight of the name - the two faces of the control are meant to
// read as the same thing, and building them from one place is what keeps them that way.
const uiPickerTitleLine = (name, badge, nameClass) => {
    const title = document.createElement('div');
    title.className = 'flex items-center gap-2 min-w-0';

    const elm = document.createElement('span');
    elm.className = nameClass;
    elm.textContent = name;
    title.append(elm);

    if (badge) {
        title.append(badge);
    }

    return title;
};

// The identifying line under the title: a note or an address when there is one, and the id,
// which is the value actually being chosen and so is always shown. One line rather than two, so
// a screenful of the dropdown is a useful number of rows to choose between.
const uiPickerDetails = (note, id) => {
    const line = uiPickerLine('text-base-content/60 truncate text-xs', '');
    line.title = id;

    if (note) {
        line.append(note + (id ? ' · ' : ''));
    }

    if (id) {
        const elm = document.createElement('span');
        elm.className = 'font-mono';
        elm.textContent = id;
        line.append(elm);
    }

    return line;
};

/**
 * Wires one picker. The adapter says what an entry is and where entries come from:
 *   value(entry)              the id the hidden input carries
 *   title(entry, nameClass)   the title line element
 *   details(entry)            the line under it
 *   load(query, trigger)      a promise of rows for a query: [{ note }] for a heading or a remark,
 *                             [{ entry }] for a choice; trigger is 'input' or 'focus'
 *   cancel()                  called when the search is left, to stop a request in flight (optional)
 *   resolve(value)            the entry for a stored value, when the adapter can tell (optional)
 *   cardAction                'clear': the card's button empties the value; 'change': it reopens
 *                             the search with the value kept until a new choice is made
 *   cardLabel, cardIcon       the button's accessible label and icon class
 *   failed                    the remark shown when load() rejects
 *
 * @param {Element} root - the [data-picker] element
 * @param {Object} adapter
 */
window.uiPicker = (root, adapter) => {
    const input = document.getElementById(root.dataset.input);
    const card = root.querySelector('[data-picker-card]');
    const search = root.querySelector('[data-picker-search]');
    const results = root.querySelector('[data-picker-results]');
    const box = search && search.querySelector('input');

    if (!input || !card || !results || !box) {
        return;
    }

    // The rendered option nodes and the entries behind them, in order, so moving the highlight
    // touches two nodes rather than re-querying the list and rewriting every row
    let options = [];
    let entries = [];
    let active = -1;
    // The entry the card shows, so leaving the search without a choice puts it back
    let current = null;
    // The load whose answer is still wanted; an older one that lands later is dropped
    let generation = 0;

    const open = () => {
        results.classList.remove('hidden');
        box.setAttribute('aria-expanded', 'true');
    };

    const close = () => {
        results.classList.add('hidden');
        results.replaceChildren();
        box.setAttribute('aria-expanded', 'false');
        box.removeAttribute('aria-activedescendant');
        options = [];
        entries = [];
        active = -1;
    };

    // Paints whichever of the two faces the control currently has. Called for every change of the
    // selection, so the card and the search box can never both be showing.
    const paint = selected => {
        current = selected;
        card.replaceChildren();

        if (!selected) {
            card.classList.add('hidden');
            search.classList.remove('hidden');
            return;
        }

        const text = document.createElement('div');
        text.className = 'min-w-0 grow';
        text.append(adapter.title(selected, 'font-medium truncate'), adapter.details(selected));

        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-text btn-sm btn-circle shrink-0';
        button.setAttribute('aria-label', adapter.cardLabel);
        const icon = document.createElement('span');
        icon.className = adapter.cardIcon + ' size-4';
        button.append(icon);
        button.addEventListener('click', () => (adapter.cardAction === 'clear' ? clearSelection(true) : change()));

        card.append(text, button);
        card.classList.remove('hidden');
        search.classList.add('hidden');
    };

    // The one writer of the hidden input. The events are what the rest of the page listens to, and
    // a programmatic value assignment fires neither on its own.
    const select = selected => {
        close();
        input.value = selected ? adapter.value(selected) : '';
        paint(selected);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
    };

    // Back to empty: the hidden input, the card and the search box all have to agree, so this is
    // one path rather than a clear button that happens to do the same three things.
    const clearSelection = focus => {
        select(null);
        box.value = '';
        if (focus) {
            box.focus();
        }
    };

    // Back to the search with the value kept: the card returns if nothing new is chosen
    const change = () => {
        paint(null);
        box.value = '';
        box.focus();
    };

    // Wraps at both ends, so ArrowUp from nothing selected lands on the last row
    const highlight = index => {
        if (options[active]) {
            options[active].classList.remove('is-active');
            options[active].setAttribute('aria-selected', 'false');
        }

        active = options.length ? (index + options.length) % options.length : -1;

        if (active < 0) {
            box.removeAttribute('aria-activedescendant');
            return;
        }

        const option = options[active];
        option.classList.add('is-active');
        option.setAttribute('aria-selected', 'true');
        box.setAttribute('aria-activedescendant', option.id);
        option.scrollIntoView({ block: 'nearest' });
    };

    const render = rows => {
        results.replaceChildren();
        options = [];
        entries = [];
        active = -1;

        for (const row of rows) {
            if (!row.entry) {
                results.append(uiPickerLine('ee-account-picker-note', row.note));
                continue;
            }

            const index = options.length;
            const option = document.createElement('button');
            option.type = 'button';
            option.id = box.id + '-option-' + index;
            option.className = 'ee-account-picker-option';
            option.setAttribute('role', 'option');
            option.setAttribute('aria-selected', 'false');
            option.append(adapter.title(row.entry, 'truncate'), adapter.details(row.entry));

            // mousedown rather than click: the box loses focus first otherwise, and the blur
            // handler closes the list out from under the click that was choosing from it
            option.addEventListener('mousedown', event => {
                event.preventDefault();
                select(row.entry);
            });
            option.addEventListener('mouseenter', () => highlight(index));

            options.push(option);
            entries.push(row.entry);
            results.append(option);
        }

        open();
    };

    const load = trigger => {
        const mine = ++generation;
        Promise.resolve(adapter.load(box.value.trim(), trigger))
            .then(rows => {
                if (mine === generation) {
                    render(rows);
                }
            })
            .catch(() => {
                if (mine === generation) {
                    render([{ note: adapter.failed }]);
                }
            });
    };

    box.addEventListener('input', () => load('input'));
    box.addEventListener('focus', () => load('focus'));

    box.addEventListener('keydown', event => {
        switch (event.key) {
            case 'ArrowDown':
                event.preventDefault();
                highlight(active + 1);
                break;
            case 'ArrowUp':
                event.preventDefault();
                highlight(active - 1);
                break;
            case 'Enter':
                if (active >= 0 && entries[active]) {
                    event.preventDefault();
                    select(entries[active]);
                }
                break;
            case 'Escape':
                box.blur();
                break;
        }
    });

    // Leaving the search without a choice: nothing in flight is wanted any more, and the card
    // comes back for a value that still stands
    box.addEventListener('blur', () => {
        generation++;
        if (adapter.cancel) {
            adapter.cancel();
        }
        close();
        paint(current);
    });

    // Reached from the card's own button and, through window.uiPickerClear() below, from a page
    // resetting a form it did not build
    root.uiPickerClear = clearSelection;
    // For a page that replaced the adapter's list: the card follows the value into the new one
    root.uiPickerRepaint = () => paint((adapter.resolve && adapter.resolve(input.value)) || null);

    // A stored value the server could resolve renders as what it names; one it could not is still
    // shown, because an id pointing at a deleted account is exactly the thing the person filling
    // in the form needs to see rather than an empty box
    let initial = null;
    try {
        initial = JSON.parse(root.dataset.selected || 'null');
    } catch (err) {
        initial = null;
    }
    paint(initial || (adapter.resolve && adapter.resolve(input.value)) || null);
};

// Accounts come from GET /admin/accounts/suggestions as the person types. A keystroke waits
// 200 ms before it becomes a request, long enough that typing an id costs one round trip rather
// than twenty, short enough to feel like the list is following along; the last answer is kept,
// so a refocus on unchanged text repaints from it instead of paying for another listing
const uiAccountPickerAdapter = () => {
    const endpoint = '/admin/accounts/suggestions';
    let timer = null;
    let inflight = null;
    let cached = null;

    // The name a person recognises. An account may carry none, in which case the address is the
    // name, and an account with neither is only ever its id
    const title = entry => entry.name || entry.email || entry.account;

    const badge = entry => (entry.state && entry.state.name ? uiPickerBadge(entry.state.name, 'badge-' + (entry.state.type || 'neutral')) : null);

    const fetchRows = query =>
        new Promise((resolve, reject) => {
            if (inflight) {
                inflight.abort();
            }
            const controller = new AbortController();
            inflight = controller;

            fetch(endpoint + (query ? '?query=' + encodeURIComponent(query) : ''), {
                headers: { accept: 'application/json' },
                signal: controller.signal
            })
                .then(res => (res.ok ? res.json() : Promise.reject(new Error('HTTP ' + res.status))))
                .then(data => {
                    const rows = (data.accounts || []).map(entry => ({ entry }));
                    if (!rows.length) {
                        rows.push({ note: 'No account matches that.' });
                    }
                    // Said out loud rather than left as a list that silently stops: the reader
                    // would otherwise read a capped list as the whole instance
                    if (data.more > 0) {
                        rows.push({ note: data.more + ' more match. Type a little more to narrow it down.' });
                    }
                    cached = { query, rows };
                    resolve(rows);
                })
                .catch(err => {
                    // an aborted request was superseded; its replacement is already on its way
                    if (err.name !== 'AbortError') {
                        reject(err);
                    }
                });
        });

    return {
        value: entry => entry.account,
        title: (entry, nameClass) => uiPickerTitleLine(title(entry), badge(entry), nameClass),
        details: entry => uiPickerDetails(entry.email && entry.email !== title(entry) ? entry.email : '', entry.account),
        cardAction: 'clear',
        cardLabel: 'Clear the selected account',
        cardIcon: 'icon-[tabler--x]',
        failed: 'The account list could not be loaded.',
        resolve: value => (value ? { account: value, name: '', email: '', state: { type: 'error', name: 'No such account' } } : null),
        load: (query, trigger) => {
            window.clearTimeout(timer);
            if (cached && cached.query === query) {
                return cached.rows;
            }
            if (trigger !== 'input') {
                return fetchRows(query);
            }
            return new Promise(resolve => {
                timer = window.setTimeout(() => resolve(fetchRows(query)), 200);
            });
        },
        cancel: () => {
            window.clearTimeout(timer);
            if (inflight) {
                inflight.abort();
                inflight = null;
            }
        }
    };
};

// Models are the list the page holds, handed over through data-models and replaced after a
// refresh with window.uiModelPickerSetModels(). With nothing typed, the recommended ones come
// first under their own heading, so the sane choice is also the easy one
const uiModelPickerAdapter = root => {
    let models = [];
    try {
        models = JSON.parse(root.dataset.models || '[]');
    } catch (err) {
        models = [];
    }

    const matches = query => models.filter(entry => !query || [entry.id, entry.name, entry.description].some(value => (value || '').toLowerCase().includes(query)));

    return {
        value: entry => entry.id,
        title: (entry, nameClass) => uiPickerTitleLine(entry.name || entry.id, entry.recommended ? uiPickerBadge('Recommended', 'badge-soft badge-success') : null, nameClass),
        details: entry => uiPickerDetails(entry.description || '', entry.id),
        cardAction: 'change',
        cardLabel: 'Choose another model',
        cardIcon: 'icon-[tabler--pencil]',
        failed: 'The model list could not be shown.',
        // a stored name the list does not carry is shown as it is: a model the key lost access to
        // is exactly the thing the person filling in the form needs to see
        resolve: value => models.find(entry => entry.id === value) || (value ? { id: value, name: value, description: 'Not in the list this API key can use' } : null),
        load: query => {
            query = query.toLowerCase();
            let shown = matches(query);
            if (!shown.length) {
                return [{ note: 'No model matches that.' }];
            }
            if (query) {
                return shown.map(entry => ({ entry }));
            }

            shown = shown.filter(entry => entry.recommended).concat(shown.filter(entry => !entry.recommended));
            const rows = [];
            let heading = null;
            for (const entry of shown) {
                const group = entry.recommended ? 'Recommended' : 'Other models';
                if (group !== heading) {
                    rows.push({ note: group });
                    heading = group;
                }
                rows.push({ entry });
            }
            return rows;
        },
        setModels: list => {
            models = Array.isArray(list) ? list : [];
        }
    };
};

const uiPickerAdapters = { account: uiAccountPickerAdapter, model: uiModelPickerAdapter };

/**
 * Clears a picker, given its hidden input.
 *
 * For pages that reset a form as a whole - the template page empties its "send test email" modal
 * every time it opens. Assigning '' to the input is not enough on its own: the card is painted from
 * the last choice, so the control would keep showing an account the form no longer carries.
 *
 * @param {Element} input - the picker's hidden input
 */
window.uiPickerClear = input => {
    const root = input && input.closest && input.closest('[data-picker]');
    if (root && root.uiPickerClear) {
        root.uiPickerClear();
    }
};
window.uiAccountPickerClear = window.uiPickerClear;

/**
 * Replaces a model picker's list, given its hidden input. The choice stands, repainted from the
 * new entries.
 *
 * @param {Element} input - the picker's hidden input
 * @param {Object[]} models - the new entries, "Default" first
 */
window.uiModelPickerSetModels = (input, models) => {
    const root = input && input.closest && input.closest('[data-picker]');
    if (root && root.uiPickerAdapter && root.uiPickerAdapter.setModels) {
        root.uiPickerAdapter.setModels(models);
        root.uiPickerRepaint();
    }
};

document.addEventListener('DOMContentLoaded', () => {
    for (let root of document.querySelectorAll('[data-picker]')) {
        const adapter = uiPickerAdapters[root.dataset.picker];
        if (adapter) {
            root.uiPickerAdapter = adapter(root);
            window.uiPicker(root, root.uiPickerAdapter);
        }
    }
});
