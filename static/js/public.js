/* global document, window */

'use strict';

/*
 * Shared behaviors for the public pages (hosted authentication form,
 * unsubscribe pages, error pages). Self-contained on purpose: no framework,
 * no admin UI scripts - just the few behaviors the static markup needs.
 * Styling lives in static/css/public.css.
 */

// Modals are native <dialog class="ee-modal"> elements opened with
// dialogElement.showModal(). The dialog handles Escape itself; this adds the
// two conventional close affordances:
//   - any element carrying data-modal-close closes its containing dialog
//   - clicking the backdrop closes the dialog (the dialog element is the
//     click target only when the click lands outside the dialog panel)
document.addEventListener('click', e => {
    let closeBtn = e.target.closest('[data-modal-close]');
    if (closeBtn) {
        let dialog = closeBtn.closest('dialog.ee-modal');
        if (dialog) {
            dialog.close();
        }
        return;
    }

    if (e.target.matches('dialog.ee-modal')) {
        let rect = e.target.getBoundingClientRect();
        let inDialog = e.clientX >= rect.left && e.clientX <= rect.right && e.clientY >= rect.top && e.clientY <= rect.bottom;
        if (!inDialog) {
            e.target.close();
        }
    }
});

// Dropdown menus are native <details class="ee-dropdown"> elements, so the
// toggle works without JavaScript; this adds the conventional dismissals:
// activating a menu item, clicking outside, and Escape. The listeners are
// only attached on pages that actually contain a dropdown.
if (document.querySelector('details.ee-dropdown')) {
    document.addEventListener('click', e => {
        let menuItemClicked = !!e.target.closest('.ee-dropdown-item');
        for (let dropdown of document.querySelectorAll('details.ee-dropdown[open]')) {
            if (menuItemClicked || !dropdown.contains(e.target)) {
                dropdown.removeAttribute('open');
            }
        }
    });

    document.addEventListener('keydown', e => {
        if (e.key !== 'Escape') {
            return;
        }
        for (let dropdown of document.querySelectorAll('details.ee-dropdown[open]')) {
            dropdown.removeAttribute('open');
        }
    });
}

// Server-side flash messages (views/partials/public_alerts.hbs): close button
// plus auto-dismiss after 15 seconds. Mirrors the admin UI behavior.
document.addEventListener('DOMContentLoaded', () => {
    let dismissFade = elm => {
        elm.classList.add('ee-fade-out');
        window.setTimeout(() => elm.remove(), 300);
    };

    let alerts = document.querySelectorAll('.ee-flash');
    if (!alerts.length) {
        return;
    }

    for (let alert of alerts) {
        let closeBtn = alert.querySelector('.ee-flash-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => dismissFade(alert));
        }
    }

    window.setTimeout(() => {
        for (let alert of document.querySelectorAll('.ee-flash')) {
            dismissFade(alert);
        }
    }, 15 * 1000);
});

/*
 * Double-submit guard for the public POST forms (the hosted authentication
 * steps and the unsubscribe pages).
 *
 * These are the slow ones: choosing a provider mints an account and hands the
 * browser to an OAuth provider, and the email/name step runs autodiscovery
 * against DNS and the provider's autoconfig endpoints. Nothing on the page
 * moves while that happens, so the button gets pressed again - and the second
 * POST loses the race against the single-use nonce the first one consumed,
 * which shows the visitor an error for a step that succeeded.
 *
 * Same mechanism as the admin guard in static/js/ui.js, which carries the full
 * reasoning; it is written out again here because the public pages share no
 * code with the admin UI.
 */
const eeSubmittedForms = new Map();

// Toggle a public-page button's busy state: unclickable, with its leading icon
// swapped for the spinner (or one added when the button has no icon).
window.eeButtonBusy = (btn, busy) => {
    btn.disabled = !!busy;

    if (btn.tagName === 'INPUT') {
        // <input type="image"> provider buttons - no children to spin
        return;
    }

    let icon = btn.querySelector('.ee-icon');
    if (!icon) {
        if (!busy) {
            return;
        }
        icon = document.createElement('span');
        icon.className = 'ee-icon';
        icon.dataset.busySpinner = 'true';
        btn.prepend(icon);
    }

    if (busy) {
        if (!('idleIcon' in icon.dataset)) {
            icon.dataset.idleIcon = Array.from(icon.classList).find(c => c.startsWith('ee-icon-')) || '';
        }
        if (icon.dataset.idleIcon) {
            icon.classList.remove(icon.dataset.idleIcon);
        }
        icon.classList.add('ee-icon-loader', 'ee-spin');
    } else if (icon.dataset.busySpinner) {
        icon.remove();
    } else {
        icon.classList.remove('ee-icon-loader', 'ee-spin');
        if (icon.dataset.idleIcon) {
            icon.classList.add(icon.dataset.idleIcon);
        }
    }
};

// Bubble phase on document, so a page that runs its own submit handling (the
// IMAP server settings step tests the connection first) has already cancelled
// the event by the time this sees it.
document.addEventListener('submit', e => {
    let form = e.target;
    if (e.defaultPrevented || !form || form.method !== 'post') {
        return;
    }

    let target = form.target.trim().toLowerCase();
    if (target && target !== '_self') {
        return;
    }

    if (eeSubmittedForms.has(form)) {
        // Already submitted once; covers implicit submission (Enter in a field)
        e.preventDefault();
        return;
    }

    let submitter = e.submitter;
    let buttons = form.querySelectorAll('button[type="submit"], button:not([type]), input[type="submit"], input[type="image"]');
    let submitterField = null;

    // The form data set is built after this event and skips disabled controls,
    // the submitter included - so a submit button that carries a name/value
    // would stop posting it. Move it into a hidden input first.
    if (submitter && submitter.name) {
        submitterField = document.createElement('input');
        submitterField.type = 'hidden';
        submitterField.name = submitter.name;
        submitterField.value = submitter.value;
        form.appendChild(submitterField);
    }

    eeSubmittedForms.set(form, { buttons, submitter, submitterField });

    for (let btn of buttons) {
        // A browser that reports no event.submitter leaves us unable to tell which button was
        // pressed, and disabling one that carries a name would drop the value the server branches
        // on - so those keep working and the latch alone does the guarding.
        if (btn === submitter || (!submitter && btn.name)) {
            continue;
        }
        btn.disabled = true;
    }
    if (submitter) {
        window.eeButtonBusy(submitter, true);
    }
});

// Back to a submitted form through the bfcache: the page comes back with the
// latch set and the buttons disabled, so clear both.
window.addEventListener('pageshow', e => {
    if (!e.persisted) {
        return;
    }
    for (let state of eeSubmittedForms.values()) {
        if (state.submitterField) {
            state.submitterField.remove();
        }
        for (let btn of state.buttons) {
            if (btn === state.submitter) {
                window.eeButtonBusy(btn, false);
            } else {
                btn.disabled = false;
            }
        }
    }
    eeSubmittedForms.clear();
});
