/* global document, window, $, ClipboardJS, FileReader, EventSource */

'use strict';

window.showToast = (message, icon) => {
    let template = `<div class="toast-header">
    <img src="/static/icons/${icon ? icon : 'info'}.svg" class="rounded mr-2">
    <strong class="mr-auto">EmailEngine</strong>
    <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close">
      <span aria-hidden="true">&times;</span>
    </button>
  </div>
  <div class="toast-body"></div>`;

    let toast = document.createElement('div');
    toast.classList.add('toast', 'show', 'fade');
    toast.dataset.delay = '5000';
    toast.dataset.autohide = 'true';

    toast.innerHTML = template;
    toast.querySelector('.toast-body').textContent = message;
    document.getElementById('toastContainer').appendChild(toast);

    $(toast).toast('show');
};

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
                    name: 'Initializing'
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
            case 'authenticationError':
            case 'connectError': {
                let errorMessage = error ? error.response : false;
                if (error) {
                    switch (error.serverResponseCode) {
                        case 'ETIMEDOUT':
                            errorMessage = 'Connection timed out. This usually happens when you are firewalled, for example are connecting to a wrong port.';
                            break;
                        case 'ClosedAfterConnectTLS':
                            errorMessage = 'Server unexpectedly closed the connection.';
                            break;
                        case 'ClosedAfterConnectText':
                            errorMessage =
                                'The server unexpectedly closed the connection. This usually happens when you try to connect to a TLS port without having TLS enabled.';
                            break;
                        case 'ECONNREFUSED':
                            errorMessage =
                                'The server refused the connection. This usually happens when the server is not running, is overloaded, or you are connecting to a wrong host or port.';
                            break;
                    }
                }

                stateLabel = {
                    type: 'danger',
                    name: 'Failed',
                    error: errorMessage
                };
                break;
            }
            case 'unset':
                stateLabel = {
                    type: 'light',
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
                    type: 'secondary',
                    name: 'Paused'
                };
                break;
            default:
                stateLabel = {
                    type: 'secondary',
                    name: 'N/A'
                };
                break;
        }

        let stateInfoElms = document.querySelectorAll(`.state-info[data-account="${account}"]`);
        if (stateInfoElms.length) {
            for (let stateInfoElm of stateInfoElms) {
                for (let val of stateInfoElm.classList.values()) {
                    if (/^badge-/.test(val) && val !== 'badge-pill') {
                        stateInfoElm.classList.remove(val);
                    }
                }

                stateInfoElm.classList.add(`badge-${stateLabel.type}`);

                stateInfoElm.innerHTML = '';
                if (stateLabel.spinner) {
                    let spinnerElm = document.createElement('i');
                    spinnerElm.classList.add('fas', 'fa-spinner', 'fa-spin', 'fa-fw');
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
                    type: 'danger',
                    name: state,
                    error: (payload && payload.error && payload.error.message) || null
                };

            default:
                return {
                    type: 'secondary',
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
                    if (/^badge-/.test(val) && val !== 'badge-pill') {
                        stateInfoElm.classList.remove(val);
                    }
                }

                stateInfoElm.classList.add(`badge-${stateLabel.type}`);

                stateInfoElm.innerHTML = '';
                if (stateLabel.spinner) {
                    let spinnerElm = document.createElement('i');
                    spinnerElm.classList.add('fas', 'fa-spinner', 'fa-spin', 'fa-fw');
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

    let crumbElm = document.getElementById('crumb');
    if (crumbElm) {
        $('.clear-alert-btn').on('closed.bs.alert', function () {
            fetch('/admin/config/clear-error', {
                method: 'post',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({
                    crumb: document.getElementById('crumb').value,
                    alert: $(this).data('clearAlert'), // eslint-disable-line no-invalid-this
                    entry: $(this).data('clearEntry') || '' // eslint-disable-line no-invalid-this
                })
            }).catch(err => console.error(err));
        });
    }
});
