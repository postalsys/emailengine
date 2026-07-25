'use strict';

// How a submitted message is put on the wire for Microsoft Graph /sendMail.
//
// Extracted from OutlookClient.submitMessage() because it is the part that has to be exactly
// right and can not be reached from a test otherwise (submitMessage needs a live account, an
// OAuth app and a Graph endpoint). The encoding is not obvious and Graph is unforgiving about
// it: the raw branch must post base64 as text/plain (a JSON body is rejected outright), while
// the structured branch must post a plain object so Graph honours an explicit from address.

/**
 * Builds the raw-MIME /sendMail request.
 *
 * @param {Buffer} raw - Complete RFC822 message
 * @param {String} oauth2UserPath - Graph user path ("me" or "users/<id>")
 * @returns {Object} { path, body, options } for OutlookOauth.request()
 */
function buildRawSendMailRequest(raw, oauth2UserPath) {
    return {
        path: `/${oauth2UserPath}/sendMail`,
        // Graph expects the MIME message base64 encoded in the request body itself
        body: Buffer.from(raw.toString('base64')),
        options: {
            // NOT application/json - Graph rejects a base64 MIME body sent as JSON
            contentType: 'text/plain',
            // sendMail answers 202 Accepted with an empty body
            returnText: true
        }
    };
}

/**
 * Builds the structured (JSON) /sendMail request used when the from address has to be honoured.
 *
 * @param {Object} messagePayload - Graph message object
 * @param {String} oauth2UserPath - Graph user path ("me" or "users/<id>")
 * @returns {Object} { path, body, options } for OutlookOauth.request()
 */
function buildStructuredSendMailRequest(messagePayload, oauth2UserPath) {
    return {
        path: `/${oauth2UserPath}/sendMail`,
        body: { message: messagePayload },
        // No contentType: an object body is serialized as application/json
        options: { returnText: true }
    };
}

module.exports = { buildRawSendMailRequest, buildStructuredSendMailRequest };
