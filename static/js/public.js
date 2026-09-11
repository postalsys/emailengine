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
    // The error page's "Go back" button. A button rather than a javascript: link, which the
    // Content-Security-Policy of the admin surface (where the error page also renders) forbids
    if (e.target.closest('[data-ee-back]')) {
        window.history.back();
        return;
    }

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
    // Attributes rather than properties: a control named `method` or `target` shadows the
    // same-named property on HTMLFormElement
    if (e.defaultPrevented || !form || (form.getAttribute('method') || 'get').toLowerCase() !== 'post') {
        return;
    }

    // The attribute, not the property: a form control named `target` shadows
    // HTMLFormElement.target, and reading the property would throw on such a form
    let target = (form.getAttribute('target') || '').trim().toLowerCase();
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

/*
 * The connection test the two hosted-form steps share: the server settings page
 * (which runs it from a button and reports into a dialog) and the checking page
 * (which runs it on load and reports inline). Everything from building the
 * request to laying out the failure rows is the same on both; only what happens
 * next differs, so that is all each page keeps.
 *
 * The text these render comes back from a mail server, so the rows are built out
 * of DOM nodes rather than markup.
 */

// Append text to an element, turning bare URLs into links. Text nodes and
// anchors are created through DOM APIs, so server-provided text is never parsed
// as HTML - this is what keeps a mail server's response text out of innerHTML.
window.eeAppendLinkified = (parentElm, text) => {
    let parts = String(text === null || text === undefined ? '' : text).split(/(https?:\/\/[^\s]+)/g);
    for (let part of parts) {
        if (/^https?:\/\//.test(part)) {
            let a = document.createElement('a');
            a.href = part;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.textContent = part;
            parentElm.appendChild(a);
        } else if (part) {
            parentElm.appendChild(document.createTextNode(part));
        }
    }
};

// Append one labelled error row (<dt> term, <dd> message) to a <dl class="ee-dl">,
// optionally followed by a smaller secondary line such as the raw server response.
window.eeAppendErrorRow = (listElm, type, text, extraLabel, extraText) => {
    let keyElm = document.createElement('dt');
    let valueContainerElm = document.createElement('dd');
    let valueElm = document.createElement('div');

    valueElm.classList.add('ee-error-text');

    keyElm.textContent = type;
    valueElm.textContent = text;

    valueContainerElm.append(valueElm);

    listElm.appendChild(keyElm);
    listElm.appendChild(valueContainerElm);

    if (extraLabel && extraText) {
        let extraLabelElm = document.createElement('div');
        extraLabelElm.textContent = extraLabel;

        let extraTextElm = document.createElement('small');
        window.eeAppendLinkified(extraTextElm, extraText);

        valueContainerElm.appendChild(extraLabelElm);
        valueContainerElm.appendChild(extraTextElm);
    }
};

// Run the hosted form's connection test for the values currently in `form`.
// Resolves with the parsed body for both a passing and a failing test - the
// endpoint reports a refused login as a 200 carrying { imap, smtp } - and with
// the error body for a 4xx/5xx, so a caller has one shape to render either way.
// `opts.timeoutMs` gives up when the request itself never comes back, which the
// server-side connection budget cannot cover.
window.eePostConnectionTest = async (form, opts) => {
    opts = opts || {};

    let body = {};
    for (let [key, value] of new FormData(form).entries()) {
        body[key] = value;
    }

    let signal;
    if (opts.timeoutMs && typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
        signal = AbortSignal.timeout(opts.timeoutMs);
    }

    const res = await fetch('/accounts/new/imap/test', {
        method: 'post',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal
    });

    if (!res.ok) {
        try {
            return await res.json();
        } catch (err) {
            console.error(err);
        }
        throw new Error(`${opts.requestFailedText || 'Request failed.'} status: ${res.status}`);
    }

    return await res.json();
};

// Lay out what a connection test reported into a <dl class="ee-dl">. Three shapes
// come back from the endpoint: a Hapi/Boom error body (403, 429), a payload
// validation failure carrying `fields`, and the per-protocol result of a test that
// actually ran. `labels` carries the translated strings, which is the only reason
// the caller has to supply anything.
window.eeRenderTestErrors = (listElm, data, labels) => {
    data = data || {};
    labels = labels || {};

    listElm.innerHTML = '';

    if (data.error && !data.fields) {
        // A Boom body carries the human-readable text in data.message and only the status name in
        // data.error ('Forbidden', 'Too Many Requests'); a caller's own catch path passes
        // { error: Error } instead, hence the fallbacks.
        window.eeAppendErrorRow(listElm, labels.error, data.message || data.error.message || data.error);
        return;
    }

    if (data.fields) {
        window.eeAppendErrorRow(listElm, labels.invalidSettings, data.message);
        for (let field of data.fields) {
            window.eeAppendErrorRow(listElm, '-', field.message);
        }
        return;
    }

    for (let [key, protocol, fallback] of [
        ['imap', 'IMAP', labels.imapFailed],
        ['smtp', 'SMTP', labels.smtpFailed]
    ]) {
        let result = data[key];
        if (result && result.success) {
            continue;
        }
        let error = (result && result.error) || fallback;
        if (result && result.responseText) {
            window.eeAppendErrorRow(listElm, protocol, error, labels.serverResponse, result.responseText);
        } else {
            window.eeAppendErrorRow(listElm, protocol, error);
        }
    }
};

// A one-shot submit for a form the page submits itself. form.submit() fires no
// submit event, so the document-level latch above never sees it - and both hosted
// form steps that use it POST to an endpoint claiming a single-use nonce, where a
// second submission is answered with an error for a step that succeeded.
//
// Returns the submit function. `opts.button` gets the busy treatment for the
// duration, `opts.validate` runs the constraint validation that submit() skips,
// and `opts.recoveryMs` re-arms the latch when the navigation never happened at
// all - the visitor cancelled it (Esc / Stop) while the page stayed alive, which
// fires no DOM event, so without it the form would be left unsubmittable. Re-arming
// is safe: the single-use nonce is the real double-submit guard, so at worst a
// later duplicate POST is refused by the server.
window.eeSubmitOnce = (form, opts) => {
    opts = opts || {};

    let submitting = false;
    let recoveryTimer = null;

    let reset = () => {
        submitting = false;
        if (recoveryTimer) {
            clearTimeout(recoveryTimer);
            recoveryTimer = null;
        }
        if (opts.button) {
            window.eeButtonBusy(opts.button, false);
        }
    };

    // Back to a submitted form through the bfcache: JS state survives, so without this
    // the latch stays set and the buttons stay disabled, deadening the form for good.
    window.addEventListener('pageshow', e => {
        if (e.persisted) {
            reset();
        }
    });

    return () => {
        if (submitting) {
            return;
        }
        // Bail without latching so the visitor can still fix the field
        if (opts.validate && !form.reportValidity()) {
            return;
        }
        submitting = true;
        if (opts.button) {
            window.eeButtonBusy(opts.button, true);
        }
        if (opts.recoveryMs) {
            recoveryTimer = setTimeout(reset, opts.recoveryMs);
        }
        form.submit();
    };
};

// Fill any input carrying data-ee-tz with the visitor's IANA time zone, so a page
// that wants one only has to mark the field.
document.addEventListener('DOMContentLoaded', () => {
    let fields = document.querySelectorAll('input[data-ee-tz]');
    if (!fields.length) {
        return;
    }
    try {
        if (typeof Intl !== 'undefined' && Intl && typeof Intl.DateTimeFormat === 'function') {
            let tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
            if (tz) {
                for (let field of fields) {
                    field.value = tz;
                }
            }
        }
    } catch (err) {
        // Intl probably not supported
    }
});
