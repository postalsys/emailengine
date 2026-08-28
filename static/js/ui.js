/* global document, window, navigator, localStorage, fetch, Event, AbortController, HSStaticMethods, HSOverlay */

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

// Repaint the #tls-label certificate badge (config/smtp and config/imap-proxy
// pages) from a certificate-check response: badge color, label text and the
// FlyonUI tooltip body that carries the status details
window.paintCertData = certData => {
    let tlsLabelElm = document.getElementById('tls-label');

    if (!certData || !certData.label || !tlsLabelElm) {
        return;
    }

    tlsLabelElm.classList.remove(`badge-${tlsLabelElm.dataset.labeltype}`);
    tlsLabelElm.classList.add(`badge-${certData.label.type}`);
    tlsLabelElm.dataset.labeltype = certData.label.type;

    tlsLabelElm.textContent = certData.label.text;

    let tooltipBodyElm = tlsLabelElm.closest('.tooltip');
    tooltipBodyElm = tooltipBodyElm && tooltipBodyElm.querySelector('.tooltip-body');
    if (tooltipBodyElm) {
        tooltipBodyElm.textContent = certData.label.title;
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
        } else {
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
    if (event.defaultPrevented || !form || form.method !== 'post') {
        return;
    }

    // A form aimed at another browsing context leaves this page in place, so
    // there is no navigation to end the busy state and nothing to latch.
    const target = form.target.trim().toLowerCase();
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
const uiAceThemes = {
    editor: { light: 'ace/theme/xcode', dark: 'ace/theme/tomorrow_night' },
    preview: { light: 'ace/theme/kuroir', dark: 'ace/theme/tomorrow_night_eighties' }
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
// Shared by the three places an mcp-scoped token is minted - the access-token form, the MCP config
// page's generator and the OAuth consent prompt - because all three ask the same question, and the
// count is the one thing a permission record does not tell a reader: the MCP surface reaches six of
// the thirteen sections, so a record that looks generous can still leave an agent holding one tool.
//
// Two filters, the same two lib/mcp/tools.js toolVisibleTo() applies to tools/list: the permission
// record, and the account binding - a credential bound to one account is never offered the tools
// that take no account argument, because there is nothing to bind them to. This is the browser's
// copy of that rule, and test/mcp-tools-test.js asserts the two agree over the whole catalog.
//
// `record` is { actions, groups, unrestricted, account }. `unrestricted` is the absence of a
// permissions record, which is a different answer from an empty one: the scopes are the only bound.
// A null record clears the element - the question does not apply to this credential at all, which
// is not the same as it having no tools.
window.uiMcpToolCount = (elm, record) => {
    let tools = JSON.parse(elm.dataset.mcpTools || '[]');

    elm.replaceChildren();
    if (!tools.length || !record) {
        return;
    }

    let bound = !!(record.account || '').trim();
    let offered = bound ? tools.filter(tool => tool.accountScoped) : tools;
    let available = record.unrestricted ? offered : offered.filter(tool => record.actions.includes(tool.action) && record.groups.includes(tool.group));

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
    let instanceWide = tools.filter(tool => !tool.accountScoped);
    if (bound && instanceWide.length) {
        let note = document.createElement('div');
        note.className = 'text-base-content/60';
        note.textContent = 'Bound to one account, so the instance-wide tools are not offered: ' + instanceWide.map(tool => tool.name).join(', ') + '.';
        elm.append(note);
    }
};

// Auto-wiring for the pages whose whole answer is a named access level (the MCP config generator
// and the consent prompt). The access-token form drives its own count instead, because its fourth
// option is a hand-built record rather than a level, and it carries no data-mcp-level-name.
document.addEventListener('DOMContentLoaded', () => {
    for (let elm of document.querySelectorAll('[data-mcp-level-name]')) {
        let presets = JSON.parse(elm.dataset.mcpPresets || '{}');
        let accountElm = elm.dataset.mcpAccountId ? document.getElementById(elm.dataset.mcpAccountId) : null;
        let radios = Array.from(document.querySelectorAll('input[name="' + elm.dataset.mcpLevelName + '"]'));

        let paint = () => {
            let selected = radios.find(radio => radio.checked);
            let level = (selected && selected.value) || 'read';
            let preset = presets[level];

            window.uiMcpToolCount(elm, {
                actions: preset ? preset.actions : [],
                groups: preset ? preset.groups : [],
                // A level the table stores as null is the unrestricted one. A level missing from
                // the table entirely is not, and counts as nothing rather than as everything -
                // the same direction every other reader of this table fails in.
                unrestricted: !preset && Object.prototype.hasOwnProperty.call(presets, level),
                account: accountElm ? accountElm.value : ''
            });
        };

        radios.forEach(radio => radio.addEventListener('change', paint));
        if (accountElm) {
            // Per keystroke, so what the binding costs is visible while the field is being filled
            // in rather than only after it loses focus
            accountElm.addEventListener('input', paint);
        }
        paint();
    }
});

// The account picker (views/partials/ui/account-picker.hbs).
//
// A free-text account id is a field only the person who already knows the id can fill in, so the
// control is a search box: type any part of an id, a name or an address, pick from the
// suggestions, and the box is replaced by a card naming what was picked.
//
// The posted value never stops being a plain account id in the hidden input the partial renders,
// and every change to it fires `input` and `change` there - so a page that watches that field (the
// MCP tool count follows it on all three pages that mint a token) needs no knowledge of this at
// all. Everything below is about which id is in that input, and nothing else reads the choice.
const uiAccountPickerEndpoint = '/admin/accounts/suggestions';

// How long a keystroke waits before it becomes a request. Long enough that typing an account id
// costs one round trip rather than twenty, short enough to feel like the list is following along.
const uiAccountPickerDebounce = 200;

// Every row is built as DOM nodes with textContent - account names and addresses are attacker-set
// (a display name arrives from a provider), and this list is rendered on an authenticated admin
// page, which is the worst place to hand one an innerHTML.
const uiAccountPickerLine = (className, text) => {
    const elm = document.createElement('div');
    elm.className = className;
    elm.textContent = text;
    return elm;
};

// The name a person recognises. An account may carry none, in which case the address is the name,
// and an account with neither is only ever its id.
const uiAccountPickerTitle = entry => entry.name || entry.email || entry.account;

const uiAccountPickerBadge = entry => {
    if (!entry.state || !entry.state.name) {
        return null;
    }
    const badge = document.createElement('span');
    badge.className = 'badge badge-sm badge-' + (entry.state.type || 'neutral');
    badge.textContent = entry.state.name;
    return badge;
};

// The title line: the name a person recognises, plus the connection state. Shared by the card and
// by a result row, which differ only in the weight of the name - the two faces of the control are
// meant to read as the same thing, and building them from one place is what keeps them that way.
const uiAccountPickerTitleLine = (entry, nameClass) => {
    const title = document.createElement('div');
    title.className = 'flex items-center gap-2 min-w-0';

    const name = document.createElement('span');
    name.className = nameClass;
    name.textContent = uiAccountPickerTitle(entry);
    title.append(name);

    const badge = uiAccountPickerBadge(entry);
    if (badge) {
        title.append(badge);
    }

    return title;
};

// The identifying line under the title: the address when it is not already the title, and the id,
// which is the value actually being chosen and so is always shown. One line rather than two, so a
// screenful of the dropdown is a useful number of accounts to choose between.
const uiAccountPickerDetails = entry => {
    const line = uiAccountPickerLine('text-base-content/60 truncate text-xs', '');
    line.title = entry.account;

    if (entry.email && entry.email !== uiAccountPickerTitle(entry)) {
        line.append(entry.email + ' \u00b7 ');
    }

    const id = document.createElement('span');
    id.className = 'font-mono';
    id.textContent = entry.account;
    line.append(id);

    return line;
};

window.uiAccountPicker = root => {
    const input = document.getElementById(root.dataset.input);
    const card = root.querySelector('[data-picker-card]');
    const search = root.querySelector('[data-picker-search]');
    const results = root.querySelector('[data-picker-results]');
    const box = search.querySelector('input');

    if (!input || !card || !results || !box) {
        return;
    }

    let entries = [];
    // The rendered option nodes, so moving the highlight touches two of them rather than
    // re-querying the list and rewriting every row
    let options = [];
    let active = -1;
    let timer = null;
    let inflight = null;
    // The last answered query and its result. A refocus on unchanged text repaints from this
    // instead of asking the server for the same page again - every one of those costs an account
    // listing, and tabbing through a form would otherwise pay for one per pass.
    let cached = null;

    const open = () => {
        results.classList.remove('hidden');
        box.setAttribute('aria-expanded', 'true');
    };

    const close = () => {
        results.classList.add('hidden');
        results.replaceChildren();
        box.setAttribute('aria-expanded', 'false');
        box.removeAttribute('aria-activedescendant');
        entries = [];
        options = [];
        active = -1;
    };

    // Paints whichever of the two faces the control currently has. Called for every change of the
    // selection, so the card and the search box can never both be showing.
    const paint = selected => {
        card.replaceChildren();

        if (!selected) {
            card.classList.add('hidden');
            search.classList.remove('hidden');
            return;
        }

        const text = document.createElement('div');
        text.className = 'min-w-0 grow';
        text.append(uiAccountPickerTitleLine(selected, 'font-medium truncate'), uiAccountPickerDetails(selected));

        const clear = document.createElement('button');
        clear.type = 'button';
        clear.className = 'btn btn-text btn-sm btn-circle shrink-0';
        clear.setAttribute('aria-label', 'Clear the selected account');
        const clearIcon = document.createElement('span');
        clearIcon.className = 'icon-[tabler--x] size-4';
        clear.append(clearIcon);
        clear.addEventListener('click', () => clearSelection(true));

        card.append(text, clear);
        card.classList.remove('hidden');
        search.classList.add('hidden');
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

    // The one writer of the hidden input. The events are what the rest of the page listens to, and
    // a programmatic value assignment fires neither on its own.
    const select = selected => {
        close();
        input.value = selected ? selected.account : '';
        paint(selected);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
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

    const render = data => {
        results.replaceChildren();
        entries = data.accounts || [];
        options = [];
        active = -1;

        if (!entries.length) {
            results.append(uiAccountPickerLine('ee-account-picker-note', 'No account matches that.'));
        }

        entries.forEach((entry, index) => {
            const option = document.createElement('button');
            option.type = 'button';
            option.id = box.id + '-option-' + index;
            option.className = 'ee-account-picker-option';
            option.setAttribute('role', 'option');
            option.setAttribute('aria-selected', 'false');
            option.append(uiAccountPickerTitleLine(entry, 'truncate'), uiAccountPickerDetails(entry));

            // mousedown rather than click: the box loses focus first otherwise, and the blur
            // handler closes the list out from under the click that was choosing from it
            option.addEventListener('mousedown', event => {
                event.preventDefault();
                select(entry);
            });
            option.addEventListener('mouseenter', () => highlight(index));

            options.push(option);
            results.append(option);
        });

        // Said out loud rather than left as a list that silently stops: the reader would otherwise
        // read a capped list as the whole instance
        if (data.more > 0) {
            results.append(uiAccountPickerLine('ee-account-picker-note', data.more + ' more match. Type a little more to narrow it down.'));
        }

        open();
    };

    const load = () => {
        const query = box.value.trim();

        if (cached && cached.query === query) {
            render(cached.data);
            return;
        }

        // A request the box has already moved on from is cancelled rather than left to finish:
        // each one is a full account listing, and a typed word would otherwise leave several of
        // them running server-side for a result nobody paints.
        if (inflight) {
            inflight.abort();
        }
        const controller = new AbortController();
        inflight = controller;

        fetch(uiAccountPickerEndpoint + (query ? '?query=' + encodeURIComponent(query) : ''), {
            headers: { accept: 'application/json' },
            signal: controller.signal
        })
            .then(res => (res.ok ? res.json() : Promise.reject(new Error('HTTP ' + res.status))))
            .then(data => {
                cached = { query, data };
                render(data);
            })
            .catch(err => {
                // An aborted request was superseded; its replacement is already on its way
                if (err.name === 'AbortError') {
                    return;
                }
                results.replaceChildren(uiAccountPickerLine('ee-account-picker-note', 'The account list could not be loaded.'));
                options = [];
                active = -1;
                open();
            });
    };

    const schedule = () => {
        window.clearTimeout(timer);
        timer = window.setTimeout(load, uiAccountPickerDebounce);
    };

    box.addEventListener('input', schedule);
    // Reopening on an unchanged box repaints from the cache, so this is only a request when the
    // text has actually moved on since the list was last filled in
    box.addEventListener('focus', load);

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
                close();
                break;
        }
    });

    box.addEventListener('blur', () => {
        window.clearTimeout(timer);
        if (inflight) {
            inflight.abort();
            inflight = null;
        }
        close();
    });

    // Reached from the card's own clear button and, through window.uiAccountPickerClear() below,
    // from a page resetting a form it did not build.
    root.uiPickerClear = clearSelection;

    // A stored value the server could resolve renders as the account it names; one it could not is
    // still shown, because an id pointing at a deleted account is exactly the thing the person
    // filling in the form needs to see rather than an empty box.
    let initial = null;
    try {
        initial = JSON.parse(root.dataset.selected || 'null');
    } catch (err) {
        initial = null;
    }
    if (!initial && input.value) {
        initial = { account: input.value, name: '', email: '', state: { type: 'error', name: 'No such account' } };
    }
    paint(initial);
};

/**
 * Clears an account picker, given its hidden input.
 *
 * For pages that reset a form as a whole - the template page empties its "send test email" modal
 * every time it opens. Assigning '' to the input is not enough on its own: the card is painted from
 * the last choice, so the control would keep showing an account the form no longer carries.
 *
 * @param {Element} input - the picker's hidden input
 */
window.uiAccountPickerClear = input => {
    const root = input && input.closest && input.closest('[data-account-picker]');
    if (root && root.uiPickerClear) {
        root.uiPickerClear();
    }
};

document.addEventListener('DOMContentLoaded', () => {
    for (let root of document.querySelectorAll('[data-account-picker]')) {
        window.uiAccountPicker(root);
    }
});
