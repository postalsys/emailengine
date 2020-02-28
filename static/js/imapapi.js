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

        fetch('/v1/settings', {
            method: 'POST', // or 'PUT'
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                webhooks: document.getElementById('settingsWebhooks').value
            })
        })
            .then(result => {
                return result.json();
            })
            .then(result => {
                console.log(result);
                if (result.error) {
                    showToast(`Failed to store settings (${result.message})`, 'alert-triangle');
                    return;
                }
                showToast('Settings updated');
            })
            .catch(err => {
                console.log(err);
                showToast(err.message);
            });
    });

    fetch('/v1/settings?webhooks=true')
        .then(result => result.json())
        .then(result => {
            console.log(result);
            document.getElementById('settingsWebhooks').value = (result && result.webhooks) || '';
        })
        .catch(err => {
            console.log(err);
            showToast(err.message, 'alert-triangle');
        });

    for (let elm of document.querySelectorAll('.domainName')) {
        elm.textContent = `${window.location.protocol}//${window.location.host}`;
    }
});
