'use strict';

// The MCP consent prompt (/admin/mcp/authorize) and the MCP config page's generator, driven in a
// browser: the page starts with instance management at Observe and no mail access, the mail
// levels appear behind their checkbox, the tool count follows both sections, and approving mints
// a token whose scopes are the sections that were not declined.
//
// The consent prompt is the one MCP surface a person reaches from outside the admin app, so its
// starting position is what an operator who reads nothing else ends up approving - which is why
// the defaults are asserted here and not only in the unit tier.
//
// Shares the Playwright webServer and Redis db 14 with the other specs (files run alphabetically
// with one worker). The `pages-` prefix matters: a spec sorting before happy-path.spec.js breaks its
// fresh-instance assertions, and only in CI.
//
// Run once:  npm run test:e2e:install
// Run suite: npm run test:e2e

const { test, expect } = require('@playwright/test');
const { useAdminSession, createApiToken, trackConsoleErrors, BASE_URL } = require('./helpers/bootstrap');

const REDIRECT_URI = 'https://claude.ai/api/mcp/auth_callback';

// A PKCE challenge of the right shape; the code is never exchanged here, so its verifier is not
// needed
const CODE_CHALLENGE = 'a'.repeat(43);

test.describe('MCP consent and generator pages', () => {
    useAdminSession(test, 'mcp');

    let apiToken;
    let clientId;

    test.beforeAll(async ({ browser, request }) => {
        const page = await browser.newPage();
        apiToken = await createApiToken(page, 'e2e mcp pages');
        await page.close();

        // The OAuth flow needs the endpoint on, OAuth sign-in on, and a Service URL to publish
        const settings = await request.post(`${BASE_URL}/v1/settings`, {
            headers: { Authorization: `Bearer ${apiToken}` },
            data: { mcpEnabled: true, mcpOAuthEnabled: true, serviceUrl: BASE_URL }
        });
        expect(settings.ok()).toBeTruthy();

        const registration = await request.post(`${BASE_URL}/mcp/oauth/register`, {
            data: { redirect_uris: [REDIRECT_URI], client_name: 'e2e consent client' }
        });
        expect(registration.status()).toBe(201);
        clientId = (await registration.json()).client_id;
    });

    const authorizeUrl = extra => {
        const params = new URLSearchParams(
            Object.assign(
                {
                    client_id: clientId,
                    redirect_uri: REDIRECT_URI,
                    response_type: 'code',
                    state: 'e2e-state',
                    code_challenge: CODE_CHALLENGE,
                    code_challenge_method: 'S256'
                },
                extra || {}
            )
        );
        return `${BASE_URL}/admin/mcp/authorize?${params.toString()}`;
    };

    test('the consent prompt starts with management at Observe and no mail access', async ({ page }) => {
        const errors = trackConsoleErrors(page);
        await page.goto(authorizeUrl());

        await expect(page.getByRole('heading', { name: /e2e consent client wants to connect/ })).toBeVisible();
        await expect(page.locator('#manage_observe')).toBeChecked();
        await expect(page.locator('#mailEnabled')).not.toBeChecked();
        // The mail levels stay out of the way until the box is ticked
        await expect(page.locator('#mailEnabledLevels')).toBeHidden();

        // One grant sentence per selected level, and only that one
        await expect(page.locator('[data-section="manage"][data-level="observe"]')).toBeVisible();
        await expect(page.locator('[data-section="manage"][data-level="operate"]')).toBeHidden();
        await expect(page.locator('[data-section="mail"]:visible')).toHaveCount(0);

        // The count follows the sections: the management observe tools, none of the mail ones
        const count = page.locator('#consentToolCount');
        await expect(count).toContainText('MCP tools available');
        await expect(count).toContainText('get_instance_stats');
        await expect(count).not.toContainText('list_messages');
        const observeOnly = (await count.textContent()).match(/(\d+) of (\d+) MCP tools available/);

        // Switching mail on brings the levels, the mail sentence and the mail tools in
        await page.locator('#mailEnabled').check();
        await expect(page.locator('#mailEnabledLevels')).toBeVisible();
        await expect(page.locator('#mailLevel_read')).toBeChecked();
        await expect(page.locator('[data-section="mail"][data-level="read"]')).toBeVisible();
        await expect(count).toContainText('list_messages');
        const withMail = (await count.textContent()).match(/(\d+) of (\d+) MCP tools available/);
        expect(Number(withMail[1])).toBeGreaterThan(Number(observeOnly[1]));
        expect(Number(withMail[2])).toBeGreaterThan(Number(observeOnly[2]));

        // and a wider management level changes the sentence shown
        await page.locator('#manage_operate').check();
        await expect(page.locator('[data-section="manage"][data-level="operate"]')).toBeVisible();
        await expect(page.locator('[data-section="manage"][data-level="observe"]')).toBeHidden();

        expect(errors).toEqual([]);
    });

    test('a client asking for the mail scope starts with mail on and no management', async ({ page }) => {
        await page.goto(authorizeUrl({ scope: 'mcp' }));

        await expect(page.locator('#mailEnabled')).toBeChecked();
        await expect(page.locator('#mailEnabledLevels')).toBeVisible();
        await expect(page.locator('#manage_none')).toBeChecked();
    });

    test('approving sends the client a code, and declining everything does not', async ({ page }) => {
        // The client's callback is off this origin; answered with an empty 204 so the browser stays
        // on the consent page and the redirect it was sent can be read off the request
        await page.route(`${REDIRECT_URI}*`, route => route.fulfill({ status: 204, body: '' }));

        await page.goto(authorizeUrl());
        await page.locator('#manage_none').check();
        await page.getByRole('button', { name: 'Approve' }).click();

        // Nothing to mint: the page says so and stays put
        await expect(page.getByText('Choose at least one kind of access')).toBeVisible();
        expect(page.url()).toContain('/admin/mcp/authorize');

        await page.locator('#manage_operate').check();
        await page.locator('#mailEnabled').check();
        const callback = page.waitForRequest(request => request.url().startsWith(REDIRECT_URI));
        await page.getByRole('button', { name: 'Approve' }).click();

        const url = new URL((await callback).url());
        expect(url.searchParams.get('code')).toMatch(/^[A-Za-z0-9_-]{20,}$/);
        expect(url.searchParams.get('state')).toBe('e2e-state');
        expect(url.searchParams.get('iss')).toBe(BASE_URL);
    });

    test('the generator mints a token for the sections chosen, management first', async ({ page, request }) => {
        const errors = trackConsoleErrors(page);
        await page.goto(`${BASE_URL}/admin/config/mcp`);
        await page.locator('#mcp-connect-tab').click();

        await expect(page.locator('#mcpGenManage_observe')).toBeChecked();
        await expect(page.locator('#mcpGenMailEnabled')).not.toBeChecked();
        await expect(page.locator('#mcpGenMailEnabledLevels')).toBeHidden();

        const count = page.locator('#mcpGenToolCount');
        await expect(count).toContainText('MCP tools available');
        await expect(count).not.toContainText('list_messages');

        const description = `e2e generator ${Date.now()}`;
        await page.locator('#mcpGenLabel').fill(description);
        await page.locator('#mcpGenMailEnabled').check();
        await expect(page.locator('#mcpGenMailEnabledLevels')).toBeVisible();
        await page.locator('#mcpGenManage_operate').check();

        await page.locator('#mcpGenSubmit').click();
        await expect(page.locator('#mcpGenResult')).toBeVisible({ timeout: 15000 });
        await expect(page.locator('#mcpGenJsonCfg')).toContainText('Authorization');

        // What reached Redis: both scopes, and the union of the two levels as an explicit list
        const listing = await request.get(`${BASE_URL}/v1/tokens?query=${encodeURIComponent(description)}`, {
            headers: { Authorization: `Bearer ${apiToken}` }
        });
        expect(listing.ok()).toBeTruthy();
        const minted = (await listing.json()).tokens.find(entry => entry.description === `MCP: ${description}`);
        expect(minted).toBeTruthy();
        expect(minted.scopes).toEqual(['mcp-manage', 'mcp']);
        expect(minted.permissions.grants.some(grant => grant.action === 'write' && grant.group === 'settings')).toBe(true);
        expect(minted.permissions.grants.some(grant => grant.action === 'read' && grant.group === 'message')).toBe(true);
        expect(minted.permissions.grants.some(grant => grant.action === 'write' && grant.group === 'message')).toBe(false);

        expect(errors).toEqual([]);
    });
});
