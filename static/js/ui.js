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
// ace instance). Clicking toggles .full-screen-div on the editor container,
// Escape exits; the editor is resized and refocused on both transitions.
window.uiEditorFullscreen = editors => {
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
            targetElm.classList.toggle('full-screen-div');
            editor.resize();
            editor.focus();
        });

        targetElm.addEventListener('keydown', e => {
            if (e.key === 'Escape' && targetElm.classList.contains('full-screen-div')) {
                targetElm.classList.remove('full-screen-div');
                editor.resize();
                editor.focus();
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
// copies the target's value (inputs) or text content. Delegated, so buttons
// inside dynamically injected markup work without re-binding. Uses the async
// Clipboard API where available; self-hosted installs served over plain HTTP
// are not a secure context, so those fall back to select() + execCommand.
document.addEventListener('click', e => {
    let btn = e.target.closest('.copy-btn');
    if (!btn) {
        return;
    }

    let target = btn.dataset.copyTarget ? document.querySelector(btn.dataset.copyTarget) : null;
    if (!target) {
        return;
    }

    let value = 'value' in target ? target.value : target.textContent;

    let copied;
    if (navigator.clipboard && window.isSecureContext) {
        copied = navigator.clipboard.writeText(value).then(
            () => true,
            () => false
        );
    } else {
        let ok = false;
        if (typeof target.select === 'function') {
            target.select();
            try {
                ok = document.execCommand('copy');
            } catch (err) {
                ok = false;
            }
        }
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
