/* global document, window, localStorage, HSStaticMethods, HSOverlay */

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
// existing showToast(message, icon) call sites keep working; icon is the
// basename of an svg under /static/icons/.
window.showToast = (message, icon) => {
    let container = document.getElementById('toastContainer');
    if (!container) {
        return;
    }

    let toast = document.createElement('div');
    toast.className = 'alert alert-soft flex items-start gap-3 shadow-lg mb-2 transition-opacity duration-300';
    toast.setAttribute('role', 'alert');

    let iconElm = document.createElement('img');
    iconElm.src = `/static/icons/${icon ? icon : 'info'}.svg`;
    iconElm.className = 'w-6 h-6 shrink-0';
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
