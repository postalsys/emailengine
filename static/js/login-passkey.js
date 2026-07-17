'use strict';

document.addEventListener('DOMContentLoaded', function () {
    var passkeyBtn = document.getElementById('passkey-login-btn');
    if (!passkeyBtn) {
        return;
    }

    if (typeof SimpleWebAuthnBrowser === 'undefined' || !SimpleWebAuthnBrowser.browserSupportsWebAuthn()) {
        passkeyBtn.classList.add('hidden');
        return;
    }

    // the label lives in its own span so status swaps keep the fingerprint icon
    var passkeyBtnLabel = document.getElementById('passkey-login-btn-label') || passkeyBtn;

    passkeyBtn.addEventListener('click', async function () {
        var errorEl = document.getElementById('passkey-error');
        errorEl.classList.add('hidden');
        passkeyBtn.disabled = true;
        passkeyBtnLabel.textContent = 'Waiting for passkey...';

        try {
            var crumbInput = document.getElementById('crumb');
            var crumbValue = crumbInput ? crumbInput.value : '';

            var optionsResp = await fetch('/admin/passkey/auth/options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ crumb: crumbValue })
            });

            var optionsData = await optionsResp.json();

            if (!optionsResp.ok || optionsData.error) {
                throw new Error(
                    optionsData.error === 'no_passkeys' ? 'No passkeys have been registered.' : optionsData.error || 'Could not start authentication.'
                );
            }

            var authResponse = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: optionsData.options });

            var nextInput = document.querySelector('input[name="next"]');
            var nextValue = nextInput ? nextInput.value : '';

            var verifyResp = await fetch('/admin/passkey/auth/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    crumb: crumbValue,
                    challengeId: optionsData.challengeId,
                    credential: authResponse,
                    next: nextValue,
                    // Reads the hidden "remember" input; always "Y" (persistent sessions hardcoded, no UI toggle)
                    remember: (document.querySelector('input[name="remember"]') || {}).value || false
                })
            });

            var verifyData = await verifyResp.json();

            if (verifyData.success) {
                window.location.href = verifyData.redirect || '/admin';
            } else {
                throw new Error(verifyData.error || 'Authentication failed.');
            }
        } catch (err) {
            if (err.name === 'NotAllowedError') {
                errorEl.textContent = 'Passkey authentication was cancelled or timed out.';
            } else {
                errorEl.textContent = err.message || 'Passkey authentication failed.';
            }
            errorEl.classList.remove('hidden');
        } finally {
            passkeyBtn.disabled = false;
            passkeyBtnLabel.textContent = 'Sign in with a passkey';
        }
    });
});
