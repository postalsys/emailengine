'use strict';

/**
 * Render-context booleans for the OAuth2 app form's base scope radios and the sections they reveal,
 * shared by the create, edit and app pages and their validation re-renders. A missing scope is an
 * app stored before base scopes existed, which used IMAP and SMTP.
 *
 * @param {string} [baseScopes] - 'imap', 'api' or 'pubsub'
 * @returns {{baseScopesApi: boolean, baseScopesImap: boolean, baseScopesPubsub: boolean}}
 */
function baseScopesContext(baseScopes) {
    return {
        baseScopesApi: baseScopes === 'api',
        baseScopesImap: baseScopes === 'imap' || !baseScopes,
        baseScopesPubsub: baseScopes === 'pubsub'
    };
}

module.exports = { baseScopesContext };
