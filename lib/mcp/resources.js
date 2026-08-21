'use strict';

// MCP resources: the connected email accounts, one resource per account.
//
// The URI scheme is emailengine://account/{account}. Reads go through the same authenticated
// server.inject() dispatch as tool calls, so what a credential can list and read here is exactly
// what it can reach over REST - an account-bound token sees its own account and nothing else,
// without this module holding any policy of its own.

const { apiInject } = require('./inject');
const { ERROR_CODES } = require('./protocol');

const ACCOUNT_URI_PREFIX = 'emailengine://account/';

// How many accounts one resources/list reports. The listing exists so an agent can find the
// account ids it should pass to tools; an instance running tens of thousands of accounts is not
// browsable that way, and list_accounts with paging arguments is the tool for it.
const MAX_LISTED_ACCOUNTS = 500;

function accountUri(account) {
    return ACCOUNT_URI_PREFIX + encodeURIComponent(account);
}

/**
 * Whether an account id survives the URI round-trip. parseAccountUri refuses decoded URI
 * structure, so an id carrying any would be listed under a URI that resources/read and the
 * listen filter then reject - such an account is reachable through the tools, just not
 * addressable as a resource, and the listings skip it rather than advertise a dead URI.
 */
function isRepresentableAccountId(account) {
    return typeof account === 'string' && !!account && !/[/?#]/.test(account);
}

/**
 * The account id an emailengine://account/{account} URI names, or null for anything else.
 * The one place the URI scheme is parsed and validated - resources/read and the
 * subscriptions/listen filter both come through here.
 */
function parseAccountUri(uri) {
    if (typeof uri !== 'string' || !uri.startsWith(ACCOUNT_URI_PREFIX)) {
        return null;
    }

    let account;
    try {
        account = decodeURIComponent(uri.slice(ACCOUNT_URI_PREFIX.length));
    } catch (err) {
        // A malformed percent-escape ('%', '%zz') throws URIError. That is an unparseable URI
        // like any other, and it has to answer as one: an uncaught throw here carries no
        // rpcCode, so the endpoint would answer 500 with no JSON-RPC envelope at all.
        return null;
    }

    if (!isRepresentableAccountId(account)) {
        return null;
    }

    return account;
}

function resourceNotFound(message) {
    const err = new Error(message);
    // Standard MCP "resource not found" error code
    err.rpcCode = -32002;
    return err;
}

function accountResource(accountData) {
    return {
        uri: accountUri(accountData.account),
        name: accountData.account,
        title: accountData.name || accountData.account,
        description: [accountData.email, accountData.state ? `state: ${accountData.state}` : null].filter(Boolean).join(', ') || undefined,
        mimeType: 'application/json'
    };
}

/**
 * Lists connected accounts as MCP resources, as far as the caller's credential can see them.
 */
async function listResources({ server, request }) {
    // An account-bound token may not enumerate the instance (the same rule REST enforces on
    // GET /v1/accounts), but it should still see its own account here rather than an error -
    // the strategy parked the binding on the request for exactly this kind of consumer
    const boundAccount = request.app && request.app.mcpBoundAccount;

    if (boundAccount) {
        if (!isRepresentableAccountId(boundAccount)) {
            return [];
        }
        const res = await apiInject({ server, request, method: 'get', url: `/v1/account/${encodeURIComponent(boundAccount)}` });
        if (res.statusCode >= 400 || !res.result) {
            return [];
        }
        return [accountResource(res.result)];
    }

    // One request: the route accepts page sizes up to 1000, so the whole cap fits a single page
    const res = await apiInject({ server, request, method: 'get', url: `/v1/accounts?page=0&pageSize=${MAX_LISTED_ACCOUNTS}` });
    if (res.statusCode >= 400 || !res.result || !Array.isArray(res.result.accounts)) {
        return [];
    }

    return res.result.accounts.filter(accountData => isRepresentableAccountId(accountData.account)).map(accountData => accountResource(accountData));
}

/**
 * Reads one account resource.
 *
 * @returns {Promise<Array>} MCP resource contents
 */
async function readResource({ server, request, uri }) {
    const account = parseAccountUri(uri);
    if (!account) {
        throw resourceNotFound(`Unknown resource: ${uri}`);
    }

    const res = await apiInject({ server, request, method: 'get', url: `/v1/account/${encodeURIComponent(account)}` });

    if (res.statusCode === 404) {
        throw resourceNotFound(`No such account: ${account}`);
    }

    if (res.statusCode >= 400) {
        const err = new Error((res.result && res.result.message) || `Failed to read account: HTTP ${res.statusCode}`);
        err.rpcCode = ERROR_CODES.INVALID_PARAMS;
        throw err;
    }

    return [
        {
            uri: accountUri(account),
            mimeType: 'application/json',
            text: JSON.stringify(res.result)
        }
    ];
}

module.exports = { listResources, readResource, accountUri, parseAccountUri, isRepresentableAccountId, ACCOUNT_URI_PREFIX };
