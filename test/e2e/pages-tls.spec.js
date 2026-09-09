'use strict';

// The TLS Certificates page (/admin/config/tls) and its upload subpage.
//
// This page replaces a checkbox on two other pages that ordered a Let's Encrypt certificate in the
// foreground when it was ticked. The behaviors worth driving through a browser are the ones that
// were impossible before it existed: seeing what each listener serves, adding a hostname and
// getting a row for it, uploading a certificate, and asking why an order would fail without waiting
// minutes for an opaque ACME error.
//
// Sorted after happy-path.spec.js by the pages- prefix, because the specs share one instance and
// run alphabetically.

const { test, expect } = require('@playwright/test');
const crypto = require('crypto');
const { ensureAdminSession, useAdminSession, trackConsoleErrors, openRowMenu: openMenu } = require('./helpers/bootstrap');

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

/**
 * Adds a hostname through the input in the certificates card header and waits for its row.
 */
async function addHostname(page, hostname) {
    await page.fill('#tlsAddHostname', hostname);
    await page.locator('#tlsAddHostnameBtn').click();
    await page.waitForURL(/\/admin\/config\/tls$/);
    await expect(page.locator(`[data-hostname-row="${hostname}"]`)).toBeVisible();
}

/**
 * The row menus on this page are labelled for certificates.
 */
async function openRowMenu(page, row) {
    await openMenu(row, 'Certificate actions');
}

/**
 * Removes a hostname from its row menu, through the confirmation dialog.
 */
async function removeHostname(page, hostname) {
    const row = page.locator(`[data-hostname-row="${hostname}"]`);
    await openRowMenu(page, row);
    await row.locator('.list-delete-btn', { hasText: 'Remove hostname' }).click();
    const modal = page.locator('#removeHostname');
    await expect(modal).toBeVisible();
    await expect(modal.locator('.delete-target-name')).toHaveText(hostname);
    await modal.locator('button[type="submit"]').click();
    await page.waitForURL(/\/admin\/config\/tls$/);
    await expect(page.locator(`[data-hostname-row="${hostname}"]`)).toHaveCount(0);
}

test.describe('TLS certificates', () => {
    useAdminSession(test, 'tls');

    test('the page leads with the listeners and a row per configured hostname', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/tls');
        await expect(page.locator('h1', { hasText: 'TLS Certificates' })).toBeVisible();

        // Nothing on the throwaway instance serves TLS, so the header badge says so instead of
        // painting the page red, and each listener tile points at where TLS is switched on.
        await expect(page.locator('h1 .badge', { hasText: 'TLS off' })).toBeVisible();
        // Off either way on this instance: the server is disabled, or enabled without TLS
        await expect(page.locator('[data-listener="smtp"]')).toContainText(/TLS is off|server is disabled/);
        await expect(page.locator('[data-listener="smtp"] a[href="/admin/config/smtp"]')).toBeVisible();
        await expect(page.locator('[data-listener="imapProxy"] a[href="/admin/config/imap-proxy"]')).toBeVisible();

        // The Service URL's own name is a row that cannot be removed
        const serviceRow = page.locator('[data-hostname-row]').first();
        await expect(serviceRow).toContainText('Service URL');
        await expect(serviceRow.locator('[data-cert-badge]')).toHaveText(/Not requested|Self-signed|Valid/);

        // The source selector: three named ways to get a certificate, one of them the default.
        await expect(page.locator('#tlsProvisioningAcme')).toBeChecked();
        await expect(page.locator('#tlsProvisioningManual')).toBeVisible();
        await expect(page.locator('#tlsProvisioningSelfSigned')).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('a hostname is added as a row and removed from its menu', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const hostname = `smtp-${crypto.randomBytes(4).toString('hex')}.example.com`;

        await page.goto('/admin/config/tls');
        await addHostname(page, hostname);

        // A mail hostname that differs from the admin URL is the normal deployment, and it used to
        // be impossible to hold a certificate for it. A public name nobody has ordered for yet is
        // neutral, not an error, and the one useful action is offered on the row.
        const row = page.locator(`[data-hostname-row="${hostname}"]`);
        await expect(row.locator('[data-cert-badge]')).toHaveText('Not requested');
        await expect(row.locator('.tls-request-btn')).toBeVisible();
        await expect(page.locator('#tls-request-all')).toBeVisible();

        // Adding it twice is answered, not duplicated
        await page.fill('#tlsAddHostname', hostname.toUpperCase());
        await page.locator('#tlsAddHostnameBtn').click();
        await page.waitForURL(/\/admin\/config\/tls$/);
        await expect(page.locator('.alert', { hasText: 'already listed' }).first()).toBeVisible();
        await expect(page.locator(`[data-hostname-row="${hostname}"]`)).toHaveCount(1);

        // Clean up so the rest of the suite sees the instance it expects
        await removeHostname(page, hostname);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test("a name Let's Encrypt cannot validate says so instead of offering to try", async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/tls');
        await addHostname(page, 'mail.internal');

        const row = page.locator('[data-hostname-row="mail.internal"]');
        await expect(row).toContainText('can not validate');
        await expect(row.locator('[data-cert-badge]')).toHaveText('Self-signed');
        await expect(row.locator('.tls-request-btn')).toHaveCount(0);

        await removeHostname(page, 'mail.internal');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('the Service URL hostname cannot be removed, and a bad name is refused', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/tls');
        const serviceRow = page.locator('[data-hostname-row]').first();
        await openRowMenu(page, serviceRow);
        await expect(serviceRow.locator('.list-delete-btn')).toHaveCount(0);
        await page.keyboard.press('Escape');

        await page.fill('#tlsAddHostname', 'not a hostname');
        await page.locator('#tlsAddHostnameBtn').click();
        await page.waitForURL(/\/admin\/config\/tls$/);
        await expect(page.locator('.alert', { hasText: 'Not a valid hostname' }).first()).toBeVisible();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test("a reachability check reports why Let's Encrypt could not validate a name", async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const hostname = `unreachable-${crypto.randomBytes(4).toString('hex')}.example.com`;

        await page.goto('/admin/config/tls');
        await addHostname(page, hostname);

        const row = page.locator(`[data-hostname-row="${hostname}"]`);
        await openRowMenu(page, row);
        await row.locator('.tls-preflight-btn').click();

        // The point of the check: a name that does not resolve is reported by name, immediately,
        // instead of surfacing minutes later as an ACME error with no explanation - and it lands on
        // the one line under the row, not in a second alert box.
        const reason = page.locator(`[data-cert-reason="${hostname}"]`);
        await expect(reason).toBeVisible();
        await expect(reason).toContainText(/Could not reach|port 80|resolve/i, { timeout: 30000 });

        await removeHostname(page, hostname);

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('an uploaded certificate is installed on its own page, listed and removable', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const material = await generatePair(['upload.example.com']);

        await page.goto('/admin/config/tls');
        await page.locator('#tls-stored a[href="/admin/config/tls/upload"]').click();
        await page.waitForURL(/\/admin\/config\/tls\/upload$/);
        await expect(page.locator('h1', { hasText: 'Upload a certificate' })).toBeVisible();

        await page.fill('#uploadCert', material.cert);
        await page.fill('#uploadKey', material.privateKey);
        await page.locator('button[type="submit"]', { hasText: 'Install certificate' }).click();
        await page.waitForURL(/\/admin\/config\/tls$/);

        await expect(page.locator('.alert', { hasText: 'upload.example.com' }).first()).toBeVisible();
        await expect(page.locator('#tls-stored')).toContainText('upload.example.com');

        // Opening the upload page again says what would be replaced
        await page.goto('/admin/config/tls/upload');
        await expect(page.locator('.alert', { hasText: 'Installing another one replaces it' })).toBeVisible();
        await expect(page.locator('button[type="submit"]', { hasText: 'Replace certificate' })).toBeVisible();

        await page.goto('/admin/config/tls');
        await page.locator('#tls-remove-uploaded').click();
        const modal = page.locator('#removeUploaded');
        await expect(modal).toBeVisible();
        await modal.locator('button[type="submit"]').click();
        await page.waitForURL(/\/admin\/config\/tls$/);
        await expect(page.locator('.alert', { hasText: 'Removed the uploaded certificate' }).first()).toBeVisible();
        await expect(page.locator('#tls-stored')).toContainText('None uploaded yet');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('a certificate whose key does not match it is refused, on the upload page', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        const material = await generatePair(['mismatch.example.com']);
        const other = await generatePair(['mismatch.example.com']);

        await page.goto('/admin/config/tls/upload');
        await page.fill('#uploadCert', material.cert);
        await page.fill('#uploadKey', other.privateKey);
        await page.locator('button[type="submit"]', { hasText: 'Install certificate' }).click();

        // Storing it and discovering the mismatch at the next restart is the wrong time: the
        // listener would be down and this page would still show it as installed. The refusal lands
        // back on the form, so the one wrong field can be fixed.
        await page.waitForURL(/\/admin\/config\/tls\/upload$/);
        await expect(page.locator('.alert', { hasText: 'does not belong to this certificate' }).first()).toBeVisible();

        await page.goto('/admin/config/tls');
        await expect(page.locator('#tls-stored')).toContainText('None uploaded yet');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('the self-signed fallback can be inspected and regenerated', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/tls');

        // Nothing has generated one on a fresh instance, and looking at the page must not either:
        // rendering it used to be able to start an ACME order. Generating it is an explicit,
        // confirmed action.
        await page.locator('#tls-regenerate-self-signed').click();
        const modal = page.locator('#regenerateSelfSigned');
        await expect(modal).toBeVisible();
        await modal.locator('button[type="submit"]').click();
        await page.waitForURL(/\/admin\/config\/tls$/);

        await expect(page.locator('#selfSignedFingerprint')).toBeVisible();
        await expect(page.locator('#selfSignedFingerprint')).toHaveText(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
        await expect(page.locator('#tls-regenerate-self-signed')).toHaveText(/Regenerate/);

        // The details dialog of a row served by the fallback names it and carries the same
        // fingerprint, so a client that pins it has one number to compare against.
        const firstRow = page.locator('[data-hostname-row]').first();
        await openRowMenu(page, firstRow);
        await firstRow.locator('.dropdown-item', { hasText: 'Details' }).click();
        const details = page.locator('#certDetails0');
        await expect(details).toBeVisible();
        await expect(details).toContainText('SHA-256 fingerprint');
        await expect(details).toContainText('Self-signed');
        await page.keyboard.press('Escape');

        expect(errors, errors.join('\n')).toHaveLength(0);
    });

    test('the certificate source is saved from its own card', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await ensureAdminSession(page);

        await page.goto('/admin/config/tls');
        await page.check('#tlsProvisioningSelfSigned');
        await page.locator('#tls-source button[type="submit"]').click();
        await page.waitForURL(/\/admin\/config\/tls$/);
        await expect(page.locator('#tlsProvisioningSelfSigned')).toBeChecked();

        // In self-signed mode no name can be requested, so the page offers nothing to click for it
        await expect(page.locator('#tls-request-all')).toHaveCount(0);
        await expect(page.locator('[data-hostname-row] .tls-request-btn')).toHaveCount(0);

        await page.check('#tlsProvisioningAcme');
        await page.locator('#tls-source button[type="submit"]').click();
        await page.waitForURL(/\/admin\/config\/tls$/);
        await expect(page.locator('#tlsProvisioningAcme')).toBeChecked();

        expect(errors, errors.join('\n')).toHaveLength(0);
    });
});
