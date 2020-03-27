'use strict';
/* global document, fetch, $, window  */

function showToast(message, icon) {
    let template = `<div class="toast-header">
    <img src="/static/icons/${icon ? icon : 'info'}.svg" class="rounded mr-2">
    <strong class="mr-auto">IMAP API</strong>
    <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close">
      <span aria-hidden="true">&times;</span>
    </button>
  </div>
  <div class="toast-body"></div>`;

    let toast = document.createElement('div');
    toast.classList.add('toast', 'show');
    toast.dataset.delay = '5000';
    toast.dataset.autohide = 'true';

    toast.innerHTML = template;
    toast.querySelector('.toast-body').textContent = message;
    document.getElementById('toastContainer').appendChild(toast);

    $(toast).toast('show');
}

function checkStatus() {
    fetch('/v1/stats')
        .then(result => {
            return result.json();
        })
        .then(result => {
            for (let elm of document.querySelectorAll('.app-version')) {
                elm.textContent = 'v' + result.version;
            }

            for (let elm of document.querySelectorAll('.stats-accounts')) {
                elm.textContent = result.accounts || 0;
            }

            ['connecting', 'connected', 'authenticationError', 'connectError'].forEach(key => {
                for (let elm of document.querySelectorAll('.stats-conn-' + key)) {
                    elm.textContent = (result.connections && result.connections[key]) || 0;
                }
            });

            setTimeout(checkStatus, 5000);
        })
        .catch(err => {
            console.error(err);
            showToast(err.message);
            setTimeout(checkStatus, 5000);
        });
}

let fetchingAccountList = false;
function showAccounts(e, state) {
    e.preventDefault();
    if (fetchingAccountList) {
        e.stopPropagation();
        return;
    }
    fetchingAccountList = true;
    fetch('/v1/accounts' + (state ? '?state=' + state : ''))
        .then(result => {
            return result.json();
        })
        .then(result => {
            fetchingAccountList = false;

            let table = document.getElementById('accountsTableBody');
            table.innerHTML = '';

            for (let accounData of result.accounts) {
                let row = document.createElement('tr');

                let thAccount = document.createElement('th');
                thAccount.textContent = accounData.account;
                row.appendChild(thAccount);

                let tdName = document.createElement('td');
                tdName.textContent = accounData.name || '';
                row.appendChild(tdName);

                let tdState = document.createElement('td');
                let state;
                switch (accounData.state) {
                    case 'authenticationError':
                        state = 'Authentication failed';
                        break;
                    case 'connectError':
                        state = 'Connection failed';
                        break;
                    default:
                        state = accounData.state.replace(/^./, c => c.toUpperCase());
                        break;
                }

                tdState.textContent = state;

                if (accounData.lastError) {
                    row.appendChild(tdState);

                    let tdDescription = document.createElement('td');
                    let tdDescriptionCode = document.createElement('code');
                    let description = accounData.lastError.response || accounData.lastError.serverResponseCode || '';
                    tdDescriptionCode.textContent = description;
                    tdDescriptionCode.title = description;
                    tdDescription.appendChild(tdDescriptionCode);
                    row.appendChild(tdDescription);
                } else {
                    tdState.setAttribute('colspan', '2');
                    row.appendChild(tdState);
                }

                let tdReconnect = document.createElement('td');
                tdReconnect.classList.add('text-right');
                let btn = document.createElement('button');
                btn.classList.add('btn', 'btn-warning', 'btn-sm');
                btn.textContent = 'Reconnect';
                btn.title = 'Request reconnecting IMAP client for this account';
                tdReconnect.appendChild(btn);
                row.appendChild(tdReconnect);

                btn.addEventListener('click', e => {
                    e.preventDefault();
                    $('#accountsModal').modal('hide');
                    showToast('Reconnect requested for ' + accounData.name || accounData.account);
                    fetch('/v1/account/' + accounData.account + '/reconnect', {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            reconnect: true
                        })
                    }).catch(err => {
                        showToast(err.message);
                        console.error(err);
                    });
                });

                table.appendChild(row);
            }

            $('#accountsModal').modal('show');
        })
        .catch(err => {
            fetchingAccountList = false;

            console.error(err);
            showToast(err.message);
            setTimeout(checkStatus, 5000);
        });
}

document.addEventListener('DOMContentLoaded', () => {
    const settingsForm = document.getElementById('settingsForm');
    const settingsNotifyText = document.getElementById('settingsNotifyText');
    const settingsNotifyTextSize = document.getElementById('settingsNotifyTextSize');

    settingsForm.addEventListener('submit', e => {
        e.preventDefault();
        settingsForm.classList.add('was-validated');
        if (settingsForm.checkValidity() === false) {
            e.stopPropagation();
            return;
        }

        let logs = {
            all: !!document.getElementById('settingsLogsAll').checked,
            accounts: Array.from(
                new Set(
                    document
                        .getElementById('settingsLogsAccounts')
                        .value.trim()
                        .split(/\r?\n/)
                        .map(a => a.trim())
                        .filter(a => a)
                )
            ),
            resetLoggedAccounts: !!document.getElementById('settingsResetLoggedAccounts').checked,
            maxLogLines: Number(document.getElementById('settingsLogsMaxLogLines').value)
        };

        fetch('/v1/settings', {
            method: 'POST', // or 'PUT'
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                webhooks: document.getElementById('settingsWebhooks').value,
                authServer: document.getElementById('settingsAuthServer').value,
                logs,
                notifyText: settingsNotifyTextSize ? !!settingsNotifyText.checked : false,
                notifyTextSize: settingsNotifyTextSize ? Number(settingsNotifyTextSize.value) : 0
            })
        })
            .then(result => {
                return result.json();
            })
            .then(result => {
                if (result.error) {
                    showToast(`Failed to store settings (${result.message})`, 'alert-triangle');
                    return;
                }
                showToast('Settings updated');
            })
            .catch(err => {
                console.error(err);
                showToast(err.message);
            });
    });

    fetch('/v1/settings?webhooks=true&authServer=true&logs=true&notifyText=true&notifyTextSize=true')
        .then(result => result.json())
        .then(result => {
            document.getElementById('settingsWebhooks').value = (result && result.webhooks) || '';
            document.getElementById('settingsAuthServer').value = (result && result.authServer) || '';

            if (settingsNotifyText) {
                settingsNotifyText.checked = !!(result && result.notifyText);
            }

            if (settingsNotifyTextSize) {
                settingsNotifyTextSize.value = (result && result.notifyTextSize) || '';
            }

            let logs = (result && result.logs) || {};
            let maxLogLines = 'maxLogLines' in logs ? logs.maxLogLines : 10000;

            document.getElementById('settingsLogsAll').checked = !!logs.all;
            document.getElementById('settingsLogsAccounts').value = logs.accounts ? logs.accounts.join('\n') : '';
            document.getElementById('settingsLogsMaxLogLines').value = maxLogLines;
        })
        .catch(err => {
            console.error(err);
            showToast(err.message, 'alert-triangle');
        });

    const logsForm = document.getElementById('logsForm');
    logsForm.addEventListener('submit', e => {
        e.preventDefault();
        logsForm.classList.add('was-validated');
        if (logsForm.checkValidity() === false) {
            e.stopPropagation();
            return;
        }

        const account = document.getElementById('logsAccount').value.trim();
        fetch(`/v1/logs/${encodeURIComponent(account)}`, {
            method: 'GET'
        })
            .then(result => {
                return result.blob();
            })
            .then(blob => {
                const a = document.createElement('a');
                a.style = 'display: none';

                const url = window.URL.createObjectURL(blob);
                a.href = url;
                document.body.appendChild(a);

                a.download = `logs-${account}.log`;
                a.click();
                window.URL.revokeObjectURL(url);
            })
            .catch(err => {
                console.error(err);
                showToast(err.message);
            });
    });

    for (let elm of document.querySelectorAll('.domainName')) {
        elm.textContent = `${window.location.protocol}//${window.location.host}`;
    }

    for (let elm of document.querySelectorAll('.stats-accounts')) {
        elm.addEventListener('click', e => showAccounts(e, false));
    }

    ['connecting', 'connected', 'authenticationError', 'connectError'].forEach(key => {
        for (let elm of document.querySelectorAll('.stats-conn-' + key)) {
            elm.addEventListener('click', e => showAccounts(e, key));
        }
    });

    checkStatus();
});
