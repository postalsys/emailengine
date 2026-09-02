'use strict';

/* global document, getComputedStyle */

// The response security headers as a real browser receives them (lib/security-headers.js). The
// unit and integration tiers assert the header text; what only a browser can show is that the
// nonce in the Content-Security-Policy is the one the parsed <script> elements hold, that the
// admin shell renders under the enforced policy without a violation, and that the surfaces
// with their own policy (bull-board, the public pages, the API) get theirs.
//
// Shares the Playwright webServer and Redis db 14 with the other specs. The filename has to sort
// after happy-path.spec.js: files run alphabetically with one worker, and happy-path asserts
// fresh-instance behaviour (it sets the FIRST admin password). Anything that bootstraps the
// instance ahead of it breaks that test.

const { test, expect } = require('@playwright/test');
const { useAdminSession, trackConsoleErrors } = require('./helpers/bootstrap');

const NONCE_RE = /'nonce-([A-Za-z0-9_-]+)'/;

test.describe('Security headers', () => {
    useAdminSession(test, 'security-headers');

    test('admin pages run their inline scripts under the nonce the header names', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        const response = await page.goto('/admin');
        expect(response.status()).toBe(200);

        const headers = response.headers();
        expect(headers['x-frame-options']).toBe('SAMEORIGIN');
        expect(headers['x-content-type-options']).toBe('nosniff');
        expect(headers['cross-origin-opener-policy']).toBe('same-origin');
        expect(headers['cache-control']).toBe('no-store');
        expect(headers['permissions-policy']).toContain('camera=()');

        const csp = headers['content-security-policy'];
        expect(csp).toMatch(/script-src 'self' 'nonce-/);
        expect(csp).toContain("frame-ancestors 'self'");
        const nonce = csp.match(NONCE_RE)[1];

        // The IDL property, not getAttribute: a CSP-aware browser hides the attribute once parsed
        const nonces = await page.evaluate(() => [...document.querySelectorAll('script:not([src])')].map(script => script.nonce));
        expect(nonces.length).toBeGreaterThan(0);
        for (const value of nonces) {
            expect(value).toBe(nonce);
        }

        // The pre-paint theme script ran, so the inline scripts did execute under the policy
        await expect(page.locator('html')).toHaveAttribute('class', /ee-app-chrome/);
        await expect(page.locator('#layout-sidebar')).toBeAttached();

        expect(errors).toHaveLength(0);
    });

    test('ACE editors are styled from linked sheets rather than injected style elements', async ({ page }) => {
        // ACE would append <style> elements, which the policy refuses without a nonce; with
        // useStrictCSP it appends none and views/partials/ace_assets.hbs links the sheets. A
        // missing sheet leaves the editor unstyled rather than erroring, hence the computed style
        const errors = trackConsoleErrors(page);

        await page.goto('/admin/config/branding');
        const editor = page.locator('.ace_editor').first();
        await expect(editor).toBeVisible();
        expect(await editor.evaluate(elm => getComputedStyle(elm).position)).toBe('relative');
        // the theme sheet paints the gutter; without it the gutter is transparent
        expect(
            await page
                .locator('.ace_gutter')
                .first()
                .evaluate(elm => getComputedStyle(elm).backgroundColor)
        ).not.toBe('rgba(0, 0, 0, 0)');
        expect(await page.evaluate(() => document.querySelectorAll('style').length)).toBe(0);

        expect(errors).toHaveLength(0);
    });

    test('each response carries its own nonce', async ({ page }) => {
        const first = (await page.goto('/admin')).headers()['content-security-policy'].match(NONCE_RE)[1];
        const second = (await page.goto('/admin/accounts')).headers()['content-security-policy'].match(NONCE_RE)[1];
        expect(second).not.toBe(first);
    });

    test('bull-board gets its own policy', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        const response = await page.goto('/admin/bull-board');
        expect(response.status()).toBe(200);
        const csp = response.headers()['content-security-policy'];
        expect(csp).toContain('https://fonts.googleapis.com');
        expect(csp).not.toMatch(/nonce/);
        expect(csp).toContain("frame-ancestors 'self'");

        await expect(page.locator('#root')).toBeVisible({ timeout: 15000 });
        expect(errors).toHaveLength(0);
    });

    test('a public page gets the relaxed policy and no framing header', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        // Without signed form data this is the public error page: same layout, same policy
        const response = await page.goto('/accounts/new');
        const headers = response.headers();
        expect(headers['content-security-policy']).toContain("script-src 'self' https: 'unsafe-inline'");
        expect(headers['content-security-policy']).not.toMatch(/nonce|frame-ancestors/);
        expect(headers['x-frame-options']).toBeUndefined();
        expect(headers['cache-control']).not.toBe('no-store');

        // the Go back button replaced a javascript: link and is wired from public.js
        await expect(page.locator('[data-ee-back]')).toBeVisible();

        // the intentional 400 itself logs a resource error; anything else (a blocked script) is a bug
        const unexpected = errors.filter(err => !/status of 400/.test(err));
        expect(unexpected, unexpected.join('\n')).toHaveLength(0);
    });

    test('an admin error page keeps admin framing with the relaxed policy of its layout', async ({ page }) => {
        const errors = trackConsoleErrors(page);

        const response = await page.goto('/admin/no-such-page');
        expect(response.status()).toBe(404);
        const headers = response.headers();
        expect(headers['content-security-policy']).toContain("script-src 'self' https: 'unsafe-inline'");
        expect(headers['content-security-policy']).toContain("frame-ancestors 'self'");
        expect(headers['x-frame-options']).toBe('SAMEORIGIN');

        await expect(page.locator('[data-ee-back]')).toBeVisible();

        const unexpected = errors.filter(err => !/status of 404/.test(err));
        expect(unexpected, unexpected.join('\n')).toHaveLength(0);
    });

    test('the API answers with the machine-facing set, on errors too', async ({ page }) => {
        // no token: the 401 is built by the error extension, which is where a header would go missing
        const response = await page.request.get('/v1/settings');
        expect(response.status()).toBe(401);
        const headers = response.headers();
        expect(headers['content-security-policy']).toBe("default-src 'none'; frame-ancestors 'none'");
        expect(headers['x-frame-options']).toBe('DENY');
        expect(headers['cache-control']).toBe('no-store');
    });
});
