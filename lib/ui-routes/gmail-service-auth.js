'use strict';

// The authentication method of a gmailService app on the admin OAuth2 app pages: the render
// context for its tab selector, and the "Detect from this host" lookup offered beside the attached
// service account (metadataServer) method.

const Joi = require('joi');

const gcpMetadata = require('../oauth/gcp-metadata');

/**
 * Render-context booleans for the gmailService authMethod tab selector. When `locked` is set the
 * method is shown but cannot be switched - it is fixed once an app has been saved.
 *
 * @param {string} [authMethod] - the selected or stored method
 * @param {boolean} [locked] - whether the method can no longer change
 * @returns {Object}
 */
function authMethodContext(authMethod, locked) {
    return {
        authMethodIsServiceKey: !authMethod || authMethod === 'serviceKey',
        authMethodIsExternalAccount: authMethod === 'externalAccount',
        authMethodIsMetadataServer: authMethod === 'metadataServer',
        authMethodLocked: !!locked
    };
}

function gmailServiceAuthRoutes({ server }) {
    // Reads the attached service account and project from the metadata server, for the "Detect
    // from this host" button on the new app form. Asks only the fixed metadata host (see
    // lib/oauth/gcp-metadata.js), and only on an explicit click, never while rendering a page
    server.route({
        method: 'POST',
        path: '/admin/config/oauth/metadata-probe',
        async handler(request) {
            try {
                let identity = await gcpMetadata.describeAttachedIdentity();
                return { success: true, serviceAccountEmail: identity.serviceAccountEmail, projectId: identity.projectId };
            } catch (err) {
                request.logger.info({ msg: 'Metadata server probe failed', code: err.code, status: err.statusCode, error: err.message });
                return { success: false, error: err.message, code: err.code || null };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.response({ error: 'Invalid request' }).code(400).takeover();
                },

                payload: Joi.object({
                    crumb: Joi.string().optional()
                })
            }
        }
    });
}

module.exports = { authMethodContext, gmailServiceAuthRoutes };
