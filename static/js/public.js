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
