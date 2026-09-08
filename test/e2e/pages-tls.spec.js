'use strict';

// The TLS Certificates page (/admin/config/tls).
//
// This page replaces a checkbox on two other pages that ordered a Let's Encrypt certificate in the
// foreground when it was ticked. The behaviors worth driving through a browser are the ones that
// were impossible before it existed: seeing what is installed, uploading a certificate, and asking
// why an order would fail without waiting minutes for an opaque ACME error.
//
// Sorted after happy-path.spec.js by the pages- prefix, because the specs share one instance and
// run alphabetically.

const { test, expect } = require('@playwright/test');
const crypto = require('crypto');
const { ensureAdminSession, useAdminSession, trackConsoleErrors } = require('./helpers/bootstrap');

/**
 * A self-signed certificate and key, generated with Node's own crypto so the spec needs no fixture
 * files and no openssl on PATH.
 *
 * Uses the same builder the product's fallback uses - it is the only pure-JavaScript certificate
 * generator in the tree, and shelling out to a CLI is not an option on every platform we ship to.
 *
 * @param {string[]} hostnames Names to cover
 * @returns {Promise<Object>} `{ cert, privateKey, fingerprint }`
 */
async function generatePair(hostnames) {
    const { createSelfSignedCertificate } = require('../../lib/tls/self-signed');
    return await createSelfSignedCertificate({ hostnames });
}

test.describe('TLS certificates', () => {
    useAdminSession(test, 'tls');

    test('the page lists a certificate card per configured hostname', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/tls');
        await expect(page.locator('h1', { hasText: 'TLS Certificates' })).toBeVisible();

        // The source selector: three named ways to get a certificate, one of them the default.
        await expect(page.locator('#tlsProvisioningAcme')).toBeChecked();
        await expect(page.locator('#tlsProvisioningManual')).toBeVisible();
        await expect(page.locator('#tlsProvisioningSelfSigned')).toBeVisible();

        // The listeners table names what each listener is serving, which nothing showed before.
        await expect(page.locator('table', { hasText: 'SMTP server' })).toBeVisible();
        await expect(page.locator('table', { hasText: 'IMAP proxy' })).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('additional hostnames get their own certificate card', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const hostname = `smtp-${crypto.randomBytes(4).toString('hex')}.example.com`;

        await page.goto('/admin/config/tls');
        await page.fill('#tlsHostnames', hostname);
        await page.locator('button[type="submit"]', { hasText: 'Save Changes' }).click();
        await page.waitForURL(/\/admin\/config\/tls$/);

        // A mail hostname that differs from the admin URL is the normal deployment, and it used to
        // be impossible to hold a certificate for it.
        await expect(page.locator(`[data-hostname-card="${hostname}"]`)).toBeVisible();
        await expect(page.locator('#tlsHostnames')).toHaveValue(new RegExp(hostname));

        // Clean up so the rest of the suite sees the instance it expects
        await page.fill('#tlsHostnames', '');
        await page.locator('button[type="submit"]', { hasText: 'Save Changes' }).click();
        await page.waitForURL(/\/admin\/config\/tls$/);
        await expect(page.locator(`[data-hostname-card="${hostname}"]`)).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test("a reachability check reports why Let's Encrypt could not validate a name", async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const hostname = `unreachable-${crypto.randomBytes(4).toString('hex')}.example.com`;

        await page.goto('/admin/config/tls');
        await page.fill('#tlsHostnames', hostname);
        await page.locator('button[type="submit"]', { hasText: 'Save Changes' }).click();
        await page.waitForURL(/\/admin\/config\/tls$/);

        const card = page.locator(`[data-hostname-card="${hostname}"]`);
        await card.locator('button', { hasText: 'Check reachability' }).click();

        // The point of the check: a name that does not resolve is reported by name, immediately,
        // instead of surfacing minutes later as an ACME error with no explanation.
        const message = page.locator(`[data-cert-message="${hostname}"]`);
        await expect(message).toBeVisible();
        await expect(message).toContainText(/Could not reach|port 80|resolve/i, { timeout: 30000 });

        await page.fill('#tlsHostnames', '');
        await page.locator('button[type="submit"]', { hasText: 'Save Changes' }).click();
        await page.waitForURL(/\/admin\/config\/tls$/);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('an uploaded certificate is installed, listed and removable', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const material = await generatePair(['upload.example.com']);

        await page.goto('/admin/config/tls');
        await page.locator('summary', { hasText: 'Upload a certificate' }).click();
        await page.fill('#uploadCert', material.cert);
        await page.fill('#uploadKey', material.privateKey);
        await page.locator('button[type="submit"]', { hasText: 'Install certificate' }).click();
        await page.waitForURL(/\/admin\/config\/tls$/);

        await expect(page.locator('.alert', { hasText: 'upload.example.com' }).first()).toBeVisible();

        await page.locator('summary', { hasText: 'Upload a certificate' }).click();
        await expect(page.locator('text=Currently installed')).toBeVisible();

        await page.locator('button[type="submit"]', { hasText: 'Remove uploaded certificate' }).click();
        await page.waitForURL(/\/admin\/config\/tls$/);
        await expect(page.locator('.alert', { hasText: 'Removed the uploaded certificate' }).first()).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('a certificate whose key does not match it is refused', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const material = await generatePair(['mismatch.example.com']);
        const other = await generatePair(['mismatch.example.com']);

        await page.goto('/admin/config/tls');
        await page.locator('summary', { hasText: 'Upload a certificate' }).click();
        await page.fill('#uploadCert', material.cert);
        await page.fill('#uploadKey', other.privateKey);
        await page.locator('button[type="submit"]', { hasText: 'Install certificate' }).click();
        await page.waitForURL(/\/admin\/config\/tls$/);

        // Storing it and discovering the mismatch at the next restart is the wrong time: the
        // listener would be down and this page would still show it as installed.
        await expect(page.locator('.alert', { hasText: 'does not belong to this certificate' }).first()).toBeVisible();

        await page.locator('summary', { hasText: 'Upload a certificate' }).click();
        await expect(page.locator('text=Currently installed')).toHaveCount(0);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('the self-signed fallback can be inspected and regenerated', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/tls');
        await page.locator('summary', { hasText: 'Self-signed fallback' }).click();

        // Nothing has generated one on a fresh instance, and looking at the page must not either:
        // rendering it used to be able to start an ACME order.
        const before = page.locator('text=No self-signed certificate has been generated yet');
        const hasNone = (await before.count()) > 0;

        if (!hasNone) {
            await page.locator('button[type="submit"]', { hasText: 'Generate a new one' }).click();
            await page.waitForURL(/\/admin\/config\/tls$/);
            await page.locator('summary', { hasText: 'Self-signed fallback' }).click();
            await expect(page.locator('text=SHA-256 fingerprint')).toBeVisible();
        }

        expect(errors, errors.join('\n')).toHaveLength(0);
    });
});
