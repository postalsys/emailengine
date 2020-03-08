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

document.addEventListener('DOMContentLoaded', () => {
    const settingsForm = document.getElementById('settingsForm');
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
                logs
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

    fetch('/v1/settings?webhooks=true&authServer=true&logs=true')
        .then(result => result.json())
        .then(result => {
            document.getElementById('settingsWebhooks').value = (result && result.webhooks) || '';
            document.getElementById('settingsAuthServer').value = (result && result.authServer) || '';

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
});
