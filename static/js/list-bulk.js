/* global document, window */
'use strict';

// Bulk actions on a resource list (views/partials/ui/bulk-actions.hbs). The selection lives in the
// row checkboxes; the floating bar shows while any is ticked. An action runs here, one item per POST
// to the bar's endpoint and a few at a time, so the dialog shows real progress, Stop takes effect
// after the requests already in flight, and the outcome names every item that was skipped or
// failed. The list says what it holds (data-one/data-many on the bar) and what each action asks
// first (data-confirm, data-typed, data-danger on its button). Every name shown comes from the
// page and is written as text, never markup.

document.addEventListener('DOMContentLoaded', () => {
    const bar = document.getElementById('bulkBar');
    const modal = document.getElementById('bulkModal');
    if (!bar || !modal) {
        return;
    }

    const CONCURRENCY = 3;
    const LIST_LIMIT = 8;

    // The verb forms of the actions a list can offer; what each one asks before it runs comes from
    // its button
    const VERBS = {
        reconnect: { verb: 'Reconnect', running: 'Reconnecting', done: 'Reconnected' },
        pause: { verb: 'Pause', running: 'Pausing', done: 'Paused' },
        resume: { verb: 'Resume', running: 'Resuming', done: 'Resumed' },
        delete: { verb: 'Delete', running: 'Deleting', done: 'Deleted' }
    };

    const ACTIONS = {};
    for (const btn of bar.querySelectorAll('[data-bulk-action]')) {
        const action = btn.dataset.bulkAction;
        const template = btn.dataset.confirm;
        ACTIONS[action] = Object.assign({}, VERBS[action], {
            typed: btn.dataset.typed || null,
            danger: !!btn.dataset.danger,
            confirm: template ? count => template.replace('{count}', plural(count)) : null
        });
    }

    const endpoint = bar.dataset.endpoint;
    const one = bar.dataset.one || 'item';
    const many = bar.dataset.many || 'items';
    const revokeOffered = !!bar.dataset.revoke;

    const $ = id => document.getElementById(id);
    const boxes = () => Array.from(document.querySelectorAll('.ee-bulk-select'));
    const selected = () => boxes().filter(box => box.checked);

    // "Name (address)": two accounts often share a display name, and a row without an address shows its name
    function label(target) {
        return target.email && target.email !== target.name ? `${target.name} (${target.email})` : target.name;
    }

    function plural(count) {
        return `${count} ${count === 1 ? one : many}`;
    }

    function show(elm, visible) {
        elm.hidden = !visible;
    }

    // ---- selection ----------------------------------------------------------------------------

    const selectAll = $('bulkSelectAll');
    const morePages = !!bar.dataset.morePages;
    const matching = Number(bar.dataset.matching) || 0;

    function updateSelection() {
        const all = boxes();
        const count = selected().length;

        for (const box of all) {
            const row = box.closest('tr');
            if (row) {
                row.classList.toggle('bg-primary/5', box.checked);
            }
        }

        show(bar, count > 0);
        show($('bulkSpacer'), count > 0);
        $('bulkCount').textContent = count;

        const wholePage = count > 0 && count === all.length;
        let scope = '';
        if (morePages) {
            scope = wholePage ? `- all on this page, ${matching - count} more match on other pages` : 'on this page';
        }
        $('bulkScope').textContent = scope;
        show($('bulkSelectPage'), !wholePage);

        if (selectAll) {
            selectAll.checked = wholePage;
            selectAll.indeterminate = count > 0 && !wholePage;
        }
    }

    function setAll(checked) {
        for (const box of boxes()) {
            box.checked = checked;
        }
        updateSelection();
    }

    if (selectAll) {
        selectAll.addEventListener('change', () => setAll(selectAll.checked));
    }
    $('bulkSelectPage').addEventListener('click', () => setAll(true));
    $('bulkClear').addEventListener('click', () => setAll(false));
    document.addEventListener('change', e => {
        if (e.target.classList && e.target.classList.contains('ee-bulk-select')) {
            updateSelection();
        }
    });

    // ---- the dialog ---------------------------------------------------------------------------

    const startBtn = $('bulkStart');
    const stopBtn = $('bulkStop');
    const retryBtn = $('bulkRetry');
    const typed = $('bulkTypeConfirm');

    let current = null; // { action, targets }
    let ran = false;
    let stopping = false;

    function setButtons(visible) {
        for (const id of ['bulkCancel', 'bulkStart', 'bulkStop', 'bulkRetry', 'bulkDone']) {
            show($(id), visible.includes(id));
        }
    }

    function setStep(step) {
        show($('bulkConfirmStep'), step === 'confirm');
        show($('bulkProgressStep'), step === 'progress');
        show($('bulkResultStep'), step === 'result');
    }

    function nameList(list, targets) {
        list.replaceChildren();
        for (const target of targets.slice(0, LIST_LIMIT)) {
            const item = document.createElement('li');
            item.textContent = label(target);
            list.appendChild(item);
        }
        if (targets.length > LIST_LIMIT) {
            const more = document.createElement('li');
            more.className = 'list-none -ms-5 text-base-content/70';
            more.textContent = `and ${targets.length - LIST_LIMIT} more`;
            list.appendChild(more);
        }
    }

    function updateStart() {
        const spec = current && ACTIONS[current.action];
        startBtn.disabled = !!(spec && spec.typed && typed.value.trim().toLowerCase() !== spec.typed);
    }

    function open(action) {
        const spec = ACTIONS[action];
        const targets = selected().map(box => ({
            id: box.value,
            name: box.dataset.name || box.value,
            email: box.dataset.email || '',
            oauth: !!box.dataset.oauth
        }));
        if (!spec || !targets.length) {
            return;
        }

        current = { action, targets };
        stopping = false;
        $('bulkTitle').textContent = `${spec.verb} ${plural(targets.length)}`;

        if (!spec.confirm) {
            window.uiModal.open(modal);
            run(targets);
            return;
        }

        $('bulkDescription').textContent = spec.confirm(targets.length);
        nameList($('bulkList'), targets);

        show($('bulkRevokeRow'), revokeOffered && action === 'delete' && targets.some(target => target.oauth));
        $('bulkRevoke').checked = false;
        show($('bulkTypeRow'), !!spec.typed);
        $('bulkTypeWord').textContent = spec.typed || '';
        typed.value = '';

        startBtn.textContent = `${spec.verb} ${plural(targets.length)}`;
        startBtn.classList.toggle('btn-error', !!spec.danger);
        startBtn.classList.toggle('btn-primary', !spec.danger);
        updateStart();

        setStep('confirm');
        setButtons(['bulkCancel', 'bulkStart']);
        window.uiModal.open(modal);
        window.setTimeout(() => (spec.typed ? typed : startBtn).focus(), 50);
    }

    for (const btn of bar.querySelectorAll('[data-bulk-action]')) {
        btn.addEventListener('click', () => open(btn.dataset.bulkAction));
    }

    typed.addEventListener('input', updateStart);
    typed.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !startBtn.disabled) {
            e.preventDefault();
            startBtn.click();
        }
    });

    startBtn.addEventListener('click', () => {
        if (current && !startBtn.disabled) {
            run(current.targets);
        }
    });

    stopBtn.addEventListener('click', () => {
        stopping = true;
        stopBtn.disabled = true;
        stopBtn.textContent = 'Stopping';
    });

    retryBtn.addEventListener('click', () => {
        if (current && current.failed && current.failed.length) {
            stopping = false;
            run(current.failed);
        }
    });

    modal.addEventListener('close.overlay', () => {
        if (ran) {
            // The list reflects what was done; the server sends a page past the end to the last one
            window.location.reload();
        }
    });

    // ---- running ------------------------------------------------------------------------------

    async function runOne(target, opts) {
        try {
            const res = await window.uiPostJson(endpoint.replace(':id', encodeURIComponent(target.id)), {
                action: current.action,
                revoke: opts.revoke
            });
            return Object.assign({}, target, res);
        } catch (err) {
            return Object.assign({}, target, { result: 'failed', error: err.message });
        }
    }

    async function run(targets) {
        const spec = ACTIONS[current.action];
        const opts = { revoke: revokeOffered && current.action === 'delete' && $('bulkRevoke').checked };
        const queue = targets.slice();
        const results = [];
        ran = true;

        setStep('progress');
        setButtons(['bulkStop']);
        stopBtn.disabled = false;
        stopBtn.textContent = 'Stop';

        const progress = $('bulkProgress');
        progress.max = targets.length;
        progress.value = 0;
        const report = () => {
            $('bulkProgressText').textContent = `${spec.running} ${results.length} of ${targets.length}`;
            progress.value = results.length;
        };
        report();

        const worker = async () => {
            while (queue.length && !stopping) {
                const target = queue.shift();
                results.push(await runOne(target, opts));
                report();
            }
        };
        await Promise.all(Array.from({ length: Math.min(CONCURRENCY, targets.length) }, worker));

        current.failed = results.filter(entry => entry.result === 'failed');
        showResults(spec, results, queue);
    }

    // One outcome line, with the items it concerns listed under it when they need naming
    function resultGroup(icon, tone, title, entries, detail) {
        const item = document.createElement('li');

        const head = document.createElement('div');
        head.className = 'flex items-center gap-2 font-medium';
        const iconElm = document.createElement('span');
        iconElm.className = `${icon} size-5 shrink-0 ${tone}`;
        head.append(iconElm, document.createTextNode(title));
        item.appendChild(head);

        if (entries && entries.length) {
            const list = document.createElement('ul');
            list.className = 'mt-1 max-h-40 list-disc overflow-y-auto ps-12 text-sm text-base-content/80';
            for (const entry of entries.slice(0, 50)) {
                const li = document.createElement('li');
                li.textContent = detail ? `${label(entry)}: ${detail(entry)}` : label(entry);
                list.appendChild(li);
            }
            if (entries.length > 50) {
                const li = document.createElement('li');
                li.textContent = `and ${entries.length - 50} more`;
                list.appendChild(li);
            }
            item.appendChild(list);
        }
        return item;
    }

    function showResults(spec, results, notRun) {
        const list = $('bulkResults');
        list.replaceChildren();

        const by = result => results.filter(entry => entry.result === result);
        const done = by('done');
        const noted = done.filter(entry => entry.note);
        const missing = by('missing');
        const failed = by('failed');

        if (done.length) {
            list.appendChild(resultGroup('icon-[tabler--circle-check]', 'text-success', `${spec.done} ${plural(done.length)}`, noted, entry => entry.note));
        }

        // Skips grouped by reason: "Skipped 3: Already paused"
        const reasons = new Map();
        for (const entry of by('skipped')) {
            const reason = entry.reason || 'Not applicable';
            reasons.set(reason, (reasons.get(reason) || []).concat(entry));
        }
        for (const [reason, entries] of reasons) {
            list.appendChild(resultGroup('icon-[tabler--circle-minus]', 'text-base-content/60', `Skipped ${plural(entries.length)}: ${reason}`, entries));
        }

        if (missing.length) {
            list.appendChild(resultGroup('icon-[tabler--circle-minus]', 'text-base-content/60', `${plural(missing.length)} no longer existed`, missing));
        }
        if (failed.length) {
            list.appendChild(
                resultGroup('icon-[tabler--alert-triangle]', 'text-error', `Failed for ${plural(failed.length)}`, failed, entry => entry.error || 'Unknown error')
            );
        }
        if (notRun.length) {
            list.appendChild(resultGroup('icon-[tabler--player-stop]', 'text-warning', `Stopped before ${plural(notRun.length)}`, notRun));
        }

        $('bulkTitle').textContent = failed.length ? `${spec.verb}: finished with errors` : `${spec.verb}: finished`;
        setStep('result');
        setButtons(failed.length ? ['bulkRetry', 'bulkDone'] : ['bulkDone']);
        $('bulkDone').focus();
    }

    updateSelection();
});
