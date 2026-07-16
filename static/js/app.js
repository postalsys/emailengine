/* global document, window, $, ClipboardJS, FileReader, EventSource */

'use strict';

// window.showToast is provided by static/js/ui.js (loaded before this file)

window.browseFileContents = function (type) {
    let iElm = document.createElement('input');
    iElm.setAttribute('type', 'file');
    iElm.style.width = '1px';
    iElm.style.height = '1px';
    iElm.style.position = 'absolute';
    iElm.style.left = '-1000px';
    iElm.style.top = '-1000px';
    document.body.appendChild(iElm);

    return new Promise((resolve, reject) => {
        iElm.addEventListener('change', () => {
            const reader = new FileReader();

            reader.addEventListener('load', event => {
                let fileContents = event.target.result;
                document.body.removeChild(iElm);

                switch (type) {
                    case 'base64': {
                        // extract base64 content from a Data URI
                        fileContents = fileContents.substring(event.target.result.indexOf(',') + 1);
                        break;
                    }
                    case 'arrayBuffer':
                    case 'text':
                    default:
                    // do nothing
                }

                resolve(fileContents);
            });

            reader.addEventListener('error', err => {
                console.error(err);
                document.body.removeChild(iElm);
                reject(new Error('Failed loading file'));
            });

            reader.addEventListener('abort', () => {
                document.body.removeChild(iElm);
                reject(new Error('Failed loading file'));
            });

            if (!iElm.files || !iElm.files[0]) {
                document.body.removeChild(iElm);
                return resolve(null);
            }

            switch (type) {
                case 'base64':
                    reader.readAsDataURL(iElm.files[0]);
                    break;
                case 'arrayBuffer':
                    reader.readAsArrayBuffer(iElm.files[0]);
                    break;
                case 'text':
                default:
                    reader.readAsText(iElm.files[0], 'UTF-8');
            }
        });

        iElm.click();
    });
};

document.addEventListener('DOMContentLoaded', () => {
    let toggleAllElements = (allElementsElm, otherElements, direction) => {
        if (!allElementsElm || !otherElements) {
            return;
        }

        const allSelected = allElementsElm.getAttribute('type') === 'checkbox' ? allElementsElm.checked : !allElementsElm.value.trim();
        for (let elm of otherElements) {
            if (elm.classList.contains('dropdown-item')) {
                if (direction && allSelected) {
                    elm.classList.add('disabled');
                } else {
                    elm.classList.remove('disabled');
                }
            } else {
                elm.disabled = direction ? allSelected : !allSelected;
            }
        }
    };

    let allElementsElms = document.querySelectorAll('.or-else-all');
    for (let allElementsElm of allElementsElms) {
        let otherElements;
        let direction = allElementsElm && allElementsElm.dataset.reverse === 'true' ? false : true;

        if (allElementsElm && allElementsElm.dataset.target) {
            otherElements = document.querySelectorAll(`.${allElementsElm.dataset.target.trim()}`);
        }

        if (!otherElements) {
            continue;
        }

        for (let elm of [allElementsElm].concat(Array.from(otherElements))) {
            elm.addEventListener('change', () => toggleAllElements(allElementsElm, otherElements, direction));
            elm.addEventListener('click', () => toggleAllElements(allElementsElm, otherElements, direction));
        }

        if (allElementsElm) {
            toggleAllElements(allElementsElm, otherElements, direction);
        }
    }

    const formatter = new Intl.RelativeTimeFormat(undefined, {
        numeric: 'auto'
    });

    const DIVISIONS = [
        { amount: 60, name: 'seconds' },
        { amount: 60, name: 'minutes' },
        { amount: 24, name: 'hours' },
        { amount: 7, name: 'days' },
        { amount: 4.34524, name: 'weeks' },
        { amount: 12, name: 'months' },
        { amount: Number.POSITIVE_INFINITY, name: 'years' }
    ];

    function formatTimeAgo(date) {
        let duration = (date - new Date()) / 1000;

        for (let i = 0; i <= DIVISIONS.length; i++) {
            const division = DIVISIONS[i];
            if (Math.abs(duration) < division.amount) {
                return formatter.format(Math.round(duration), division.name);
            }
            duration /= division.amount;
        }
    }
    window.formatTimeAgo = formatTimeAgo;

    let updateRelativeTimes = () => {
        document.querySelectorAll('.relative-time').forEach(entry => {
            let time = new Date(entry.dataset.time);
            if (time) {
                entry.textContent = formatTimeAgo(time);
            }
        });
    };

    updateRelativeTimes();
    setInterval(updateRelativeTimes, 15 * 1000);

    for (let t of document.querySelectorAll('.local-time')) {
        if (!t.dataset.time) {
            continue;
        }
        let date = new Date(t.dataset.time);
        t.textContent = new Intl.DateTimeFormat().format(date);
    }

    for (let t of document.querySelectorAll('.local-date-time')) {
        if (!t.dataset.time) {
            continue;
        }
        let date = new Date(t.dataset.time);
        t.textContent = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium', dateStyle: 'short' }).format(date);
    }

    let clip = new ClipboardJS('.copy-btn');
    if (!clip) {
        console.log('Can not set up clipboard');
    }

    // enable tooltips
    $('[data-toggle="tooltip"]').tooltip();
    $('[data-toggle="popover"]').popover();

    function dropfile(elm, file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            elm.value = (e.target.result || '').trim();
            elm.focus();
            elm.select();
        };
        reader.readAsText(file, 'UTF-8');
    }

    for (let elm of document.querySelectorAll('.droptxt')) {
        elm.addEventListener('dragenter', () => {
            elm.classList.add('dragover');
        });

        elm.addEventListener('dragleave', () => {
            elm.classList.remove('dragover');
        });

        elm.addEventListener('drop', e => {
            e.preventDefault();
            elm.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            dropfile(elm, file);
        });
    }

    for (let elm of document.querySelectorAll('.autoselect')) {
        elm.addEventListener('click', () => {
            elm.focus();
            elm.select();
        });
    }

    for (let elm of document.querySelectorAll('.cur-base-url')) {
        let origin = elm.dataset.origin || window.location.origin;
        if (elm.getAttribute('type') === 'text') {
            elm.value = origin;
        } else {
            elm.textContent = origin;
        }
    }

    function updateStateIndicators(data) {
        let { account, key: state, payload } = data;
        let error = payload && payload.error;

        let stateLabel;

        switch (state) {
            case 'init':
                stateLabel = {
                    type: 'info',
                    name: 'Initializing',
                    spinner: true
                };
                break;
            case 'connecting':
                stateLabel = {
                    type: 'info',
                    name: 'Connecting'
                };
                break;
            case 'syncing':
                stateLabel = {
                    type: 'info',
                    name: 'Syncing',
                    spinner: true
                };
                break;
            case 'connected':
                stateLabel = {
                    type: 'success',
                    name: 'Connected'
                };
                break;
            case 'disabled':
                stateLabel = {
                    type: 'neutral',
                    name: 'Disabled'
                };
                break;

            case 'authenticationError':
            case 'connectError': {
                let errorMessage = error ? error.response : false;
                if (error) {
                    switch (error.serverResponseCode) {
                        case 'ETIMEDOUT':
                            errorMessage = 'Connection timed out. Check your firewall settings and verify the port number.';
                            break;
                        case 'ClosedAfterConnectTLS':
                            errorMessage = 'Server closed the connection unexpectedly. Try again or check server status.';
                            break;
                        case 'ClosedAfterConnectText':
                            errorMessage =
                                'Server closed the connection. This often means TLS is required but not enabled.';
                            break;
                        case 'ECONNREFUSED':
                            errorMessage =
                                'Connection refused. Verify the server is running and check the hostname and port.';
                            break;
                    }
                }

                stateLabel = {
                    type: 'error',
                    name: 'Connection failed',
                    error: errorMessage
                };
                break;
            }
            case 'unset':
                stateLabel = {
                    type: 'neutral',
                    name: 'Not syncing'
                };
                break;
            case 'disconnected':
                stateLabel = {
                    type: 'warning',
                    name: 'Disconnected'
                };
                break;
            case 'paused':
                stateLabel = {
                    type: 'neutral',
                    name: 'Paused'
                };
                break;
            default:
                stateLabel = {
                    type: 'neutral',
                    name: 'N/A'
                };
                break;
        }

        let stateInfoElms = document.querySelectorAll(`.state-info[data-account="${account}"]`);
        if (stateInfoElms.length) {
            for (let stateInfoElm of stateInfoElms) {
                for (let val of stateInfoElm.classList.values()) {
                    if (/^badge-/.test(val)) {
                        stateInfoElm.classList.remove(val);
                    }
                }

                stateInfoElm.classList.add(`badge-${stateLabel.type}`);

                stateInfoElm.innerHTML = '';
                if (stateLabel.spinner) {
                    let spinnerElm = document.createElement('span');
                    spinnerElm.classList.add('icon-[tabler--loader-2]', 'animate-spin', 'size-3.5', 'align-text-bottom');
                    let textElm = document.createElement('span');
                    textElm.textContent = ' ' + stateLabel.name;
                    stateInfoElm.appendChild(spinnerElm);
                    stateInfoElm.appendChild(textElm);
                } else {
                    stateInfoElm.textContent = stateLabel.name;
                }

                if (stateLabel.error) {
                    stateInfoElm.dataset.title = 'Connection error';
                    stateInfoElm.dataset.content = stateLabel.error;
                    $(stateInfoElm).popover('enable');
                } else {
                    stateInfoElm.dataset.title = '';
                    stateInfoElm.dataset.content = '';
                    $(stateInfoElm).popover('disable');
                }
            }
        }
    }

    function formatSmtpState(state, payload) {
        switch (state) {
            case 'suspended':
            case 'exited':
            case 'disabled':
                return {
                    type: 'warning',
                    name: state
                };

            case 'spawning':
            case 'initializing':
                return {
                    type: 'info',
                    name: state,
                    spinner: true
                };

            case 'listening':
                return {
                    type: 'success',
                    name: state
                };

            case 'failed':
                return {
                    type: 'error',
                    name: state,
                    error: (payload && payload.error && payload.error.message) || null
                };

            default:
                return {
                    type: 'neutral',
                    name: 'N/A'
                };
        }
    }

    function updateSmtpStateIndicators(data) {
        let { key: state, payload } = data;

        let stateLabel = formatSmtpState(state, payload);

        let stateInfoElms = document.querySelectorAll(`.state-info[data-type="smtp"]`);
        if (stateInfoElms.length) {
            for (let stateInfoElm of stateInfoElms) {
                for (let val of stateInfoElm.classList.values()) {
                    if (/^badge-/.test(val)) {
                        stateInfoElm.classList.remove(val);
                    }
                }

                stateInfoElm.classList.add(`badge-${stateLabel.type}`);

                stateInfoElm.innerHTML = '';
                if (stateLabel.spinner) {
                    let spinnerElm = document.createElement('span');
                    spinnerElm.classList.add('icon-[tabler--loader-2]', 'animate-spin', 'size-3.5', 'align-text-bottom');
                    let textElm = document.createElement('span');
                    textElm.textContent = ' ' + stateLabel.name;
                    stateInfoElm.appendChild(spinnerElm);
                    stateInfoElm.appendChild(textElm);
                } else {
                    stateInfoElm.textContent = stateLabel.name;
                }

                if (stateLabel.error) {
                    stateInfoElm.dataset.title = 'Connection error';
                    stateInfoElm.dataset.content = stateLabel.error;
                    $(stateInfoElm).popover('enable');
                } else {
                    stateInfoElm.dataset.title = '';
                    stateInfoElm.dataset.content = '';
                    $(stateInfoElm).popover('disable');
                }
            }
        }
    }

    // live account/SMTP state updates; only layouts that mark themselves opt in
    // (the login and public layouts must not open an authenticated SSE stream)
    if (document.body.dataset.sseChanges === 'true') {
        const evtSource = new EventSource('/admin/changes');
        evtSource.onmessage = function (e) {
            let data;
            try {
                data = JSON.parse(e.data);
            } catch (err) {
                // ignore?
                console.error('Failed to process event', e.data, err);
            }
            switch (data && data.type) {
                case 'state':
                    updateStateIndicators(data);
                    break;
                case 'smtpServerState':
                    updateSmtpStateIndicators(data);
                    break;
            }
        };

        evtSource.onerror = function (e) {
            console.log('EventSource failed.', e);
        };
    }

    let crumbElm = document.getElementById('crumb');
    if (crumbElm) {
        // dismissable error alerts: the close button removes the alert and
        // clears the stored error server-side (replaces the old Bootstrap
        // data-dismiss="alert" + closed.bs.alert contract)
        for (let alertElm of document.querySelectorAll('.clear-alert-btn')) {
            let closeBtn = alertElm.querySelector('[data-dismiss="alert"]');
            if (!closeBtn) {
                continue;
            }
            closeBtn.addEventListener('click', () => {
                alertElm.remove();
                fetch('/admin/config/clear-error', {
                    method: 'post',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({
                        crumb: document.getElementById('crumb').value,
                        alert: alertElm.dataset.clearAlert,
                        entry: alertElm.dataset.clearEntry || ''
                    })
                }).catch(err => console.error(err));
            });
        }
    }

    for (let f of document.querySelectorAll('form.pending-form')) {
        f.addEventListener('submit', () => {
            for (let b of f.querySelectorAll('button[type="submit"], button:not([type])')) {
                b.disabled = true;
                b.classList.add('disabled');
                let icon = b.querySelector('span[class*="icon-["]');
                if (icon) {
                    for (let [, className] of icon.classList.entries()) {
                        if (/^icon-\[/.test(className)) {
                            icon.classList.remove(className);
                            icon.dataset.oldIcon = className;
                            icon.classList.add('icon-updated');
                        }
                    }
                    icon.classList.add('icon-[tabler--loader-2]', 'animate-spin');
                }
            }
        });
    }
});

window.addEventListener('pageshow', () => {
    for (let icon of document.querySelectorAll('.icon-updated')) {
        icon.classList.remove('icon-[tabler--loader-2]', 'animate-spin', 'icon-updated');
        if (icon.dataset.oldIcon) {
            icon.classList.add(icon.dataset.oldIcon);
            icon.dataset.oldIcon = '';
        }
    }

    for (let b of document.querySelectorAll('.disabled')) {
        b.classList.remove('disabled');
        b.disabled = false;
    }
});
