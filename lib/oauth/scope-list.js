'use strict';

// The scope list an OAuth2 application actually requests, derived from what is stored on it. Kept in a
// leaf module because two callers need it from opposite ends of the dependency graph: lib/oauth2-apps.js
// builds the authentication URL from it, and lib/oauth/scope-checker.js decides from it what an
// application can do - the latter must not pull the Redis chain in to ask.

// The last path segment of a scope URL, which is the short name the scope presets on the OAuth2 app
// form write into skipScopes ("Mail.ReadWrite", "gmail.modify"). Derived from the scope's own prefix
// rather than compared against a list of hosts: the Outlook defaults are requested under
// graph.microsoft.com on the global cloud but under graph.microsoft.us, dod-graph.microsoft.us or
// microsoftgraph.chinacloudapi.cn on GCC High, DoD and China, and a host list that named only the
// global one left every default scope of such an application in place.
function shortScopeName(scope) {
    const separator = scope.lastIndexOf('/');
    return separator < 0 ? scope : scope.slice(separator + 1);
}

function formatExtraScopes(extraScopes, baseScopes, defaultScopesList, skipScopes, scopePrefix) {
    let defaultScopes;

    // An empty entry would match the short name of a scope URL ending in a slash
    skipScopes = [].concat(skipScopes || []).filter(entry => entry);

    if (Array.isArray(defaultScopesList)) {
        defaultScopes = defaultScopesList;
    } else {
        defaultScopes = (baseScopes && defaultScopesList[baseScopes]) || defaultScopesList.imap;
    }

    if (!extraScopes && !skipScopes.length) {
        return defaultScopes;
    }

    extraScopes = extraScopes || [];

    let extras = [];
    for (let extraScope of extraScopes) {
        if (defaultScopes.includes(extraScope) || (scopePrefix && defaultScopes.includes(`${scopePrefix}/${extraScope}`))) {
            // skip existing
            continue;
        }
        extras.push(extraScope);
    }

    let result = extras.length ? extras.concat(defaultScopes) : defaultScopes;

    if (skipScopes.length) {
        result = result.filter(scope => !skipScopes.some(skipScope => scope === skipScope || shortScopeName(scope) === skipScope));
    }

    return result;
}

module.exports = { shortScopeName, formatExtraScopes };
