/* global document, window, navigator, localStorage, HSStaticMethods, HSOverlay */

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

// Copy-to-clipboard buttons: a .copy-btn with data-copy-target="#selector"
// copies the target's value (inputs), ACE editor content (a mounted
// ui/code-editor div) or text content. Delegated, so buttons inside
// dynamically injected markup work without re-binding. Uses the async
// Clipboard API where available; self-hosted installs served over plain HTTP
// are not a secure context, so those fall back to execCommand on a throwaway
// textarea (a selection on the target itself would not work for password
// inputs or ACE editors, which only render the visible lines).
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

    copied.then(ok => {
        if (!ok) {
            window.showToast('Failed to copy to clipboard', 'alert-triangle');
            return;
        }
        let icon = btn.querySelector('[class*="icon-"]');
        if (icon && icon.classList.replace('icon-[tabler--copy]', 'icon-[tabler--check]')) {
            window.setTimeout(() => icon.classList.replace('icon-[tabler--check]', 'icon-[tabler--copy]'), 1500);
        }
    });
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

// Toggle an async action button's busy state: disable the button and swap its
// icon span to a spinner while busy, restoring the original icon after
window.uiButtonBusy = (btn, busy) => {
    btn.disabled = !!busy;
    const icon = btn.querySelector('[class*="icon-["]');
    if (!icon) {
        return;
    }
    if (busy) {
        if (!('idleIcon' in icon.dataset)) {
            icon.dataset.idleIcon = Array.from(icon.classList).find(c => c.startsWith('icon-[')) || '';
        }
        if (icon.dataset.idleIcon) {
            icon.classList.remove(icon.dataset.idleIcon);
        }
        icon.classList.add('icon-[tabler--loader-2]', 'animate-spin');
    } else {
        icon.classList.remove('icon-[tabler--loader-2]', 'animate-spin');
        if (icon.dataset.idleIcon) {
            icon.classList.add(icon.dataset.idleIcon);
        }
    }
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

