'use strict';

document.addEventListener('DOMContentLoaded', function () {
    var registerBtn = document.getElementById('register-passkey-btn');
    if (!registerBtn) {
        return;
    }

    if (typeof SimpleWebAuthnBrowser === 'undefined' || !SimpleWebAuthnBrowser.browserSupportsWebAuthn()) {
        registerBtn.disabled = true;
        registerBtn.title = 'Your browser does not support passkeys';
        return;
    }

    registerBtn.addEventListener('click', function () {
        var nameInput = document.getElementById('passkey-name');
        if (nameInput) {
            nameInput.value = '';
        }
        var errorEl = document.getElementById('passkey-register-error');
        var successEl = document.getElementById('passkey-register-success');
        if (errorEl) {
            errorEl.style.display = 'none';
        }
        if (successEl) {
            successEl.style.display = 'none';
        }
        var confirmBtn = document.getElementById('passkey-register-confirm-btn');
        if (confirmBtn) {
            confirmBtn.disabled = false;
        }
        $('#registerPasskeyModal').modal('show');
    });

    var confirmBtn = document.getElementById('passkey-register-confirm-btn');
    if (!confirmBtn) {
        return;
    }

    confirmBtn.addEventListener('click', async function () {
        var errorEl = document.getElementById('passkey-register-error');
        var successEl = document.getElementById('passkey-register-success');
        errorEl.style.display = 'none';
        successEl.style.display = 'none';
        confirmBtn.disabled = true;

        var nameInput = document.getElementById('passkey-name');
        var name = (nameInput && nameInput.value.trim()) || 'Unnamed passkey';

        var crumbInput = document.getElementById('security-crumb');
        var crumbValue = crumbInput ? crumbInput.value : '';

        try {
            var optionsResp = await fetch('/admin/account/passkeys/register/options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ crumb: crumbValue })
            });

            if (!optionsResp.ok) {
                var errData = await optionsResp.json();
                throw new Error(errData.error || 'Could not start registration.');
            }

            var optionsData = await optionsResp.json();

            var regResponse = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: optionsData.options });

            var verifyResp = await fetch('/admin/account/passkeys/register/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    crumb: crumbValue,
                    challengeId: optionsData.challengeId,
                    name: name,
                    credential: regResponse
                })
            });

            var verifyData = await verifyResp.json();

            if (verifyData.success) {
                successEl.style.display = 'block';
                setTimeout(function () {
                    window.location.reload();
                }, 1000);
            } else {
                throw new Error(verifyData.error || 'Registration failed.');
            }
        } catch (err) {
            if (err.name === 'NotAllowedError') {
                errorEl.textContent = 'Passkey registration was cancelled or timed out.';
            } else {
                errorEl.textContent = err.message || 'Registration failed.';
            }
            errorEl.style.display = 'block';
            confirmBtn.disabled = false;
        }
    });
});
