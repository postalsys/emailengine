'use strict';

// The two connection-security checkboxes of the admin account form, for the IMAP and the SMTP
// section alike: "Allow invalid certificates" (`tls.rejectUnauthorized`) and "Require STARTTLS"
// (`requireTLS`, see lib/create-imap-client.js and lib/utils/require-tls.js). The schema,
// rendering and saving are each written once here, because the two sections used to carry their
// own copies of the same four comparisons. The gateway forms share the STARTTLS field.
//
// A value is written only when the effective state changes: an untouched form save must not add
// keys to the stored connection object, since any imap diff forces a reconnect.

const { formBoolean } = require('../schemas');

// required unless the stored object says otherwise
const storedRequireTls = stored => !(stored && stored.requireTLS === false);

/**
 * The "Require STARTTLS" checkbox of a form, unticked when the field is absent.
 *
 * @returns {Object} joi schema
 */
function requireTlsFormField() {
    return formBoolean().default(false).example(true).description('Require STARTTLS when direct TLS is off').label('RequireTLS');
}

/**
 * The form fields of the two checkboxes for one section.
 *
 * @param {String} prefix - 'imap' or 'smtp', the form field prefix
 * @returns {Object} joi schemas, to spread into the form's payload schema
 */
function securityFormFields(prefix) {
    return {
        [`${prefix}_requireTLS`]: requireTlsFormField(),
        [`${prefix}_tls_ignoreCertErrors`]: formBoolean()
            .default(false)
            .example(false)
            .description('Allow connections to servers with invalid TLS certificates for this account')
    };
}

/**
 * The form values of the two checkboxes for one section.
 *
 * @param {String} prefix - 'imap' or 'smtp', the form field prefix
 * @param {Object} [stored] - the stored connection object
 * @returns {Object} `<prefix>_tls_ignoreCertErrors` and `<prefix>_requireTLS`
 */
function securityFormValues(prefix, stored) {
    return {
        [`${prefix}_tls_ignoreCertErrors`]: !!(stored && stored.tls && stored.tls.rejectUnauthorized === false),
        [`${prefix}_requireTLS`]: storedRequireTls(stored)
    };
}

/**
 * Applies the two checkboxes of a submitted form to the update of one section.
 *
 * @param {Object} payload - the validated form payload
 * @param {String} prefix - 'imap' or 'smtp'
 * @param {Object} [stored] - the stored connection object
 * @param {Object} target - the object the section's update keys are collected on
 * @param {Object} tls - the tls object being built for the update (the stored one, or empty)
 */
function applySecurityForm(payload, prefix, stored, target, tls) {
    if (payload[`${prefix}_tls_ignoreCertErrors`] !== (tls.rejectUnauthorized === false)) {
        tls.rejectUnauthorized = !payload[`${prefix}_tls_ignoreCertErrors`];
    }
    if (payload[`${prefix}_requireTLS`] !== storedRequireTls(stored)) {
        target.requireTLS = payload[`${prefix}_requireTLS`];
    }
}

module.exports = { requireTlsFormField, securityFormFields, securityFormValues, applySecurityForm };
