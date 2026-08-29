'use strict';

// A passkey is only tellable apart in the security-page list by the name given here, and the
// field defaults to "Unnamed passkey" when left empty, so the modal opens with the current
// browser and platform filled in. It stays fully editable - this is a starting point, not a
// claim about the authenticator, which may well be a phone or a security key.
// Lookup tables rather than if/else ladders: a new Chromium fork is then a row, not a branch.
// Order matters - the Chromium-based browsers all keep "Chrome" in the string, and Chrome itself
// keeps "Safari".
var PASSKEY_PLATFORMS = [
    [/iPhone|iPad|iPod/, 'iOS'],
    [/Android/, 'Android'],
    [/Mac OS X|Macintosh/, 'macOS'],
    [/Windows/, 'Windows'],
    [/Linux/, 'Linux']
];

var PASSKEY_BROWSERS = [
    [/Edg\//, 'Edge'],
    [/OPR\/|Opera/, 'Opera'],
    [/Firefox\//, 'Firefox'],
    [/Chrome\//, 'Chrome'],
    [/Safari\//, 'Safari']
];

function matchUserAgent(table, ua) {
    for (var i = 0; i < table.length; i++) {
        if (table[i][0].test(ua)) {
            return table[i][1];
        }
    }
    return '';
}

function suggestPasskeyName() {
    var ua = navigator.userAgent || '';

    // userAgentData.platform first, the way static/js/ui.js reads it: it is the value that
    // survives the user-agent string reduction browsers are rolling out
    var platform = (navigator.userAgentData && navigator.userAgentData.platform) || matchUserAgent(PASSKEY_PLATFORMS, ua);
    var browser = matchUserAgent(PASSKEY_BROWSERS, ua);

    if (browser && platform) {
        return browser + ' on ' + platform;
    }
    return browser || platform || '';
}

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
            nameInput.value = suggestPasskeyName();
        }
        var passwordInput = document.getElementById('passkey-current-password');
        if (passwordInput) {
            passwordInput.value = '';
        }
        var errorEl = document.getElementById('passkey-register-error');
        var successEl = document.getElementById('passkey-register-success');
        if (errorEl) {
            errorEl.classList.add('hidden');
        }
        if (successEl) {
            successEl.classList.add('hidden');
        }
        var confirmBtn = document.getElementById('passkey-register-confirm-btn');
        if (confirmBtn) {
            confirmBtn.disabled = false;
        }
        uiModal.open('#registerPasskeyModal');
    });

    var confirmBtn = document.getElementById('passkey-register-confirm-btn');
    if (!confirmBtn) {
        return;
    }

    confirmBtn.addEventListener('click', async function () {
        var errorEl = document.getElementById('passkey-register-error');
        var successEl = document.getElementById('passkey-register-success');
        errorEl.classList.add('hidden');
        successEl.classList.add('hidden');
        confirmBtn.disabled = true;

        var nameInput = document.getElementById('passkey-name');
        var name = (nameInput && nameInput.value.trim()) || 'Unnamed passkey';

        var passwordInput = document.getElementById('passkey-current-password');
        var password = passwordInput ? passwordInput.value : '';

        var crumbInput = document.getElementById('security-crumb');
        var crumbValue = crumbInput ? crumbInput.value : '';

        try {
            var optionsResp = await fetch('/admin/account/passkeys/register/options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ crumb: crumbValue, password: password })
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
                successEl.classList.remove('hidden');
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
            errorEl.classList.remove('hidden');
            confirmBtn.disabled = false;
        }
    });
});
