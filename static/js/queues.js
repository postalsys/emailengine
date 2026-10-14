'use strict';

// Client behavior for the queue browser (/admin/queues and its pages).
//
// The pages arrive as finished HTML. This file only adds what needs a browser: the counts and
// the paused badges are repainted from /admin/queues/counts every few seconds (polling, on
// purpose - a busy instance fans out thousands of queue events a minute, and none of them is
// worth pushing to a page that only shows totals), and the clean action fills in its dialog.
// Retry and send-now are plain forms, and a removal goes through the shared .list-delete-btn
// flow in ui.js, like every other list page; neither needs anything from here.

(() => {
    const POLL_INTERVAL = 10 * 1000;

    const countElements = () => document.querySelectorAll('[data-queue-count]');

    function paintCounts(queues) {
        for (const elm of countElements()) {
            const [queue, state] = (elm.dataset.queueCount || '').split(':');
            const status = queues[queue];
            if (!status || !status.counts || typeof status.counts[state] !== 'number') {
                continue;
            }
            const count = status.counts[state];
            elm.textContent = count.toLocaleString();
            // the overview tiles mute a zero and colour anything else by its state
            if (elm.dataset.countVariant) {
                elm.classList.toggle(`text-${elm.dataset.countVariant}`, count > 0);
                elm.classList.toggle('text-base-content/40', count === 0);
            }
        }

        // what shows only while the queue is paused, and what shows only while it runs
        for (const elm of document.querySelectorAll('[data-queue-paused]')) {
            const status = queues[elm.dataset.queuePaused];
            if (status) {
                elm.classList.toggle('hidden', !status.isPaused);
            }
        }
        for (const elm of document.querySelectorAll('[data-queue-active-only]')) {
            const status = queues[elm.dataset.queueActiveOnly];
            if (status) {
                elm.classList.toggle('hidden', status.isPaused);
            }
        }
    }

    let polling = false;
    async function poll() {
        if (document.hidden || polling || !countElements().length) {
            return;
        }
        polling = true;
        try {
            const res = await fetch('/admin/queues/counts', { headers: { accept: 'application/json' }, credentials: 'same-origin' });
            if (!res.ok) {
                return;
            }
            const data = await res.json();
            if (data && data.queues) {
                paintCounts(data.queues);
            }
        } catch (err) {
            // a failed poll changes nothing on the page; the next one may succeed
        } finally {
            polling = false;
        }
    }

    setInterval(poll, POLL_INTERVAL);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            poll();
        }
    });

    // Cleaning a state: the one dialog on the page is filled in from the button that opened it
    document.addEventListener('click', e => {
        const btn = e.target.closest('.queue-clean-btn');
        if (!btn) {
            return;
        }
        e.preventDefault();

        const modal = document.getElementById('cleanQueue');
        if (!modal) {
            return;
        }

        const form = modal.querySelector('form');
        if (form) {
            form.setAttribute('action', `/admin/queues/${encodeURIComponent(btn.dataset.queue)}/clean`);
        }
        const stateField = document.getElementById('clean-state');
        if (stateField) {
            stateField.value = btn.dataset.state;
        }
        const title = document.getElementById('clean-queue-title');
        if (title) {
            title.textContent = `Remove ${btn.dataset.state} ${btn.dataset.noun || 'entries'}`;
        }
        const stateName = modal.querySelector('.clean-state-name');
        if (stateName) {
            stateName.textContent = btn.dataset.state;
        }
        const queueName = modal.querySelector('.clean-queue-name');
        if (queueName) {
            queueName.textContent = btn.dataset.queueLabel || btn.dataset.queue;
        }
        const note = modal.querySelector('.clean-queue-note');
        if (note) {
            note.textContent = note.dataset[`note${btn.dataset.state.charAt(0).toUpperCase()}${btn.dataset.state.slice(1)}`] || '';
        }

        window.uiModal.open(modal);
    });
})();
