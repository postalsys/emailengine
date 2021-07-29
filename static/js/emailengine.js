'use strict';
/* global document, fetch, $, window, moment, confirm */

function showToast(message, icon) {
    let template = `<div class="toast-header">
    <img src="/static/icons/${icon ? icon : 'info'}.svg" class="rounded mr-2">
    <strong class="mr-auto">EmailEngine</strong>
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
    // calculate seconds from the start of current day (in local time)
    let now = new Date();
    let today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    let seconds = Math.max(Math.ceil((now.getTime() - today.getTime()) / 1000), 1);

    fetch(`/v1/stats?seconds=${seconds}`)
        .then(result => result.json())
        .then(result => {
            for (let elm of document.querySelectorAll('.app-version')) {
                elm.textContent = 'v' + result.version;
            }

            for (let elm of document.querySelectorAll('.app-license')) {
                elm.textContent = result.license;
            }

            if (!/\bMIT\b/.test(result.license)) {
                for (let elm of document.querySelectorAll('.no-mit-license')) {
                    elm.classList.remove('d-none');
                }
            }

            for (let elm of document.querySelectorAll('.stats-accounts')) {
                elm.textContent = result.accounts || 0;
            }

            ['connecting', 'connected', 'authenticationError', 'connectError'].forEach(key => {
                for (let elm of document.querySelectorAll('.stats-conn-' + key)) {
                    elm.textContent = (result.connections && result.connections[key]) || 0;
                }
            });

            for (let key of ['events:messageNew', 'events:messageDeleted', 'webhooks:success', 'webhooks:fail', 'apiCall:success', 'apiCall:fail']) {
                for (let elm of document.querySelectorAll('.stats-counter-' + key.replace(/:/g, '_'))) {
                    elm.textContent = (result.counters && result.counters[key]) || 0;
                }
            }

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
    fetch('/v1/accounts?page=0&pageSize=1000' + (state ? '&state=' + state : ''))
        .then(result => result.json())
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
                } else if (accounData.syncTime) {
                    row.appendChild(tdState);

                    let tdDescription = document.createElement('td');
                    let tdDescriptionCode = document.createElement('em');

                    let description = `Last change ${moment(accounData.syncTime).fromNow()}`;

                    tdDescriptionCode.textContent = description;
                    tdDescriptionCode.title = moment(accounData.syncTime).format('LLL');
                    tdDescription.appendChild(tdDescriptionCode);
                    row.appendChild(tdDescription);
                } else {
                    tdState.setAttribute('colspan', '2');
                    row.appendChild(tdState);
                }

                let createButton = options => {
                    let btn = document.createElement('button');
                    btn.classList.add('btn', `btn-${options.style}`, 'btn-sm');
                    btn.title = options.title;

                    let ico = document.createElement('img');
                    ico.alt = '';
                    ico.setAttribute('src', `/static/icons/${options.icon}.svg`);
                    btn.appendChild(ico);

                    btn.style.marginLeft = '5px';

                    return btn;
                };

                let createReconnectButton = () => {
                    let btn = createButton({
                        title: 'Request reconnecting IMAP client for this account',
                        icon: 'arrow-clockwise',
                        style: 'warning'
                    });

                    btn.addEventListener('click', e => {
                        e.preventDefault();
                        $('#accountsModal').modal('hide');
                        showToast('Reconnect requested for ' + accounData.name || accounData.account);
                        fetch('/v1/account/' + encodeURIComponent(accounData.account) + '/reconnect', {
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

                    return btn;
                };

                let createDeleteButton = () => {
                    let btn = createButton({
                        title: 'Request deletion of this account',
                        icon: 'trash',
                        style: 'danger'
                    });

                    btn.addEventListener('click', e => {
                        e.preventDefault();
                        if (!confirm('Are you sure?')) {
                            return;
                        }
                        $('#accountsModal').modal('hide');
                        showToast('Requested account deletion for ' + accounData.name || accounData.account);
                        fetch('/v1/account/' + encodeURIComponent(accounData.account), {
                            method: 'DELETE'
                        }).catch(err => {
                            showToast(err.message);
                            console.error(err);
                        });
                    });

                    return btn;
                };

                let tdReconnect = document.createElement('td');
                tdReconnect.classList.add('text-right');

                tdReconnect.appendChild(createReconnectButton());
                tdReconnect.appendChild(createDeleteButton());

                row.appendChild(tdReconnect);

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

function showAddAccount() {
    document.getElementById('addAccountForm').classList.remove('was-validated');
    $('#addAccountModal').modal('show');
}

function submitAddAccount() {
    let isOauthAccount = document.getElementById('AddAccountOauth2Enable').checked;

    let account = {
        account: document.getElementById('addAccountFormId').value.trim(),
        name: document.getElementById('addAccountFormName').value.trim(),
        imap: !isOauthAccount
            ? {
                  auth: {
                      user: document.getElementById('addAccountIMAPUser').value.trim(),
                      pass: document.getElementById('addAccountIMAPPass').value.trim()
                  },
                  host: document.getElementById('addAccountIMAPHost').value.trim(),
                  port: Number(document.getElementById('addAccountIMAPPort').value.trim()),
                  secure: document.getElementById('addAccountIMAPSecure').checked,
                  tls: {
                      rejectUnauthorized: !document.getElementById('addAccountIMAPSecure').checked
                  },
                  resyncDelay: Number(document.getElementById('addAccountIMAPResyncDelay').value.trim())
              }
            : false,
        smtp:
            document.getElementById('addAccountSMTPEnable').checked && !isOauthAccount
                ? {
                      auth: {
                          user: document.getElementById('addAccountSMTPUser').value.trim(),
                          pass: document.getElementById('addAccountSMTPPass').value.trim()
                      },
                      host: document.getElementById('addAccountSMTPHost').value.trim(),
                      port: Number(document.getElementById('addAccountSMTPPort').value.trim()),
                      secure: document.getElementById('addAccountSMTPSecure').checked,
                      tls: {
                          rejectUnauthorized: !document.getElementById('addAccountSMTPSecure').checked
                      }
                  }
                : false,
        oauth2: isOauthAccount
            ? {
                  auth: {
                      user: document.getElementById('addAccountOauth2User').value.trim()
                  }
              }
            : false
    };

    $('#addAccountModal').modal('hide');

    fetch('/v1/account', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(account)
    })
        .then(result => result.json())
        .then(result => {
            // reset all fields
            document.getElementById('addAccountFormId').value = '';
            document.getElementById('addAccountFormName').value = '';
            document.getElementById('addAccountIMAPUser').value = '';
            document.getElementById('addAccountIMAPPass').value = '';
            document.getElementById('addAccountIMAPHost').value = '';
            document.getElementById('addAccountIMAPPort').value = '';
            document.getElementById('addAccountIMAPSecure').checked = false;
            document.getElementById('addAccountIMAPResyncDelay').value = '900';
            document.getElementById('addAccountSMTPEnable').checked = false;
            document.getElementById('addAccountSMTPUser').value = '';
            document.getElementById('addAccountSMTPPass').value = '';
            document.getElementById('addAccountSMTPHost').value = '';
            document.getElementById('addAccountSMTPPort').value = '';
            document.getElementById('addAccountSMTPSecure').checked = false;

            document.getElementById('AddAccountOauth2Enable').checked = false;

            document.getElementById('add-account-imap-tab').classList.remove('disabled');
            document.getElementById('add-account-smtp-tab').classList.remove('disabled');

            // select imap tab by default
            document.getElementById('add-account-oauth2-tab').classList.remove('active');
            document.getElementById('add-account-smtp-tab').classList.remove('active');
            document.getElementById('add-account-imap-tab').classList.add('active');

            document.getElementById('add-account-oauth2').classList.remove('active');
            document.getElementById('add-account-smtp').classList.remove('active');
            document.getElementById('add-account-imap').classList.add('active');

            document.getElementById('addAccountIMAPSection').disabled = false;
            document.getElementById('addAccountSMTPSection').disabled = true;
            document.getElementById('addAccountOauth2Section').disabled = true;

            if (result.error) {
                showToast(`Failed to create an account (${result.message})`, 'alert-triangle');
                return;
            }

            if (result.redirect) {
                // Most probably Oauth2 redirect
                window.location = result.redirect;
                return;
            }

            showToast('Account created');
        })
        .catch(err => {
            console.error(err);
            showToast(err.message);
        });
}

document.addEventListener('DOMContentLoaded', () => {
    const settingsForm = document.getElementById('settingsForm');
    const settingsNotifyText = document.getElementById('settingsNotifyText');
    const settingsNotifyTextSize = document.getElementById('settingsNotifyTextSize');
    const settingsNotifyHeaders = document.getElementById('settingsNotifyHeaders');
    const settingsWebhookEvents = document.getElementById('settingsWebhookEvents');
    const infoEventTypes = document.getElementById('infoEventTypes');

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

        const payload = {
            webhooks: document.getElementById('settingsWebhooks').value,
            logs,
            notifyText: settingsNotifyTextSize ? !!settingsNotifyText.checked : false,
            notifyTextSize: settingsNotifyTextSize ? Number(settingsNotifyTextSize.value) : 0,

            notifyHeaders: settingsNotifyHeaders
                ? settingsNotifyHeaders.value
                      .trim()
                      .split(',')
                      .map(entry => entry.trim())
                      .filter(entry => entry)
                : undefined,

            webhookEvents: settingsWebhookEvents
                ? settingsWebhookEvents.value
                      .trim()
                      .split(',')
                      .map(entry => entry.trim())
                      .filter(entry => entry)
                : undefined,

            gmailClientId: document.getElementById('settingsGmailClientId').value,
            gmailClientSecret: document.getElementById('settingsGmailClientSecret').value,
            gmailRedirectUrl: document.getElementById('settingsGmailRedirectUrl').value
        };

        fetch('/v1/settings', {
            method: 'POST', // or 'PUT'
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        })
            .then(result => result.json())
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

    let keysToFetch = [
        'webhooks',
        'authServer',
        'logs',
        'notifyText',
        'notifyTextSize',
        'notifyHeaders',
        'webhookEvents',
        'eventTypes',
        'gmailClientId',
        'gmailClientSecret',
        'gmailRedirectUrl'
    ];

    fetch(`/v1/settings?${keysToFetch.map(key => `${key}=true`).join('&')}`)
        .then(result => result.json())
        .then(result => {
            document.getElementById('settingsWebhooks').value = (result && result.webhooks) || '';
            document.getElementById('settingsAuthServer').value = (result && result.authServer) || '';

            document.getElementById('settingsGmailClientId').value = (result && result.gmailClientId) || '';
            document.getElementById('settingsGmailClientSecret').value = '';
            if (result.gmailClientSecret) {
                document.getElementById('settingsGmailClientSecret').placeholder = '(client secret is set but not disclosed)';
            }
            document.getElementById('settingsGmailRedirectUrl').value = (result && result.gmailRedirectUrl) || window.location.origin + '/oauth';

            if (settingsNotifyText) {
                settingsNotifyText.checked = !!(result && result.notifyText);
            }

            if (settingsNotifyTextSize) {
                settingsNotifyTextSize.value = (result && result.notifyTextSize) || '';
            }

            if (settingsNotifyHeaders) {
                settingsNotifyHeaders.value = (result && result.notifyHeaders && result.notifyHeaders.join(', ')) || '';
            }

            if (settingsWebhookEvents) {
                settingsWebhookEvents.value = (result && result.webhookEvents && result.webhookEvents.join(', ')) || '*';
            }

            if (result.eventTypes && infoEventTypes) {
                infoEventTypes.textContent = result.eventTypes.join(', ');
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
            .then(result => result.blob())
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

    document.getElementById('addAccountButton').addEventListener('click', e => {
        e.preventDefault();
        showAddAccount();
    });

    let addAccountSMTPEnableElm = document.getElementById('addAccountSMTPEnable');
    let toggleAddAccountSMTPSection = () => {
        let section = document.getElementById('addAccountSMTPSection');
        if (addAccountSMTPEnableElm.checked) {
            section.disabled = false;
        } else {
            section.disabled = true;
        }
    };
    addAccountSMTPEnableElm.addEventListener('click', toggleAddAccountSMTPSection);

    let addAccountOauth2EnableElm = document.getElementById('AddAccountOauth2Enable');
    let toggleAddAccountOauth2Tabs = () => {
        if (addAccountOauth2EnableElm.checked) {
            document.getElementById('add-account-imap-tab').classList.add('disabled');
            document.getElementById('add-account-smtp-tab').classList.add('disabled');

            // force imap/smtp fieldsets to disabled, otherwise form does not pass validation
            document.getElementById('addAccountIMAPSection').disabled = true;
            document.getElementById('addAccountSMTPSection').disabled = true;
            document.getElementById('addAccountOauth2Section').disabled = false;
        } else {
            document.getElementById('add-account-imap-tab').classList.remove('disabled');
            document.getElementById('add-account-smtp-tab').classList.remove('disabled');

            document.getElementById('addAccountIMAPSection').disabled = false;
            toggleAddAccountSMTPSection();
            document.getElementById('addAccountOauth2Section').disabled = true;
        }
    };
    addAccountOauth2EnableElm.addEventListener('click', toggleAddAccountOauth2Tabs);

    let addAccountForm = document.getElementById('addAccountForm');
    addAccountForm.addEventListener('submit', e => {
        e.preventDefault();
        addAccountForm.classList.add('was-validated');
        if (addAccountForm.checkValidity() === false) {
            e.stopPropagation();
            return;
        }
        submitAddAccount();
    });

    checkStatus();
});
