'use strict';

const imapTools = require('../imap-tools');
const imapHandler = require('../handler/imap-handler');

/*

handles both FETCH and UID FETCH

a1 FETCH 1:* (FLAGS BODY BODY.PEEK[HEADER.FIELDS (SUBJECT DATE FROM)] BODY.PEEK[]<0.28> BODY.PEEK[]<0> BODY[HEADER] BODY[1.2])
a1 FETCH 1 (BODY.PEEK[HEADER] BODY.PEEK[TEXT])
a1 FETCH 1 (INTERNALDATE UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (date subject from content-type to cc bcc message-id in-reply-to references)])
*/

module.exports = {
    state: 'Selected',
    disableNotifications: true,

    schema: [
        {
            name: 'range',
            type: 'sequence'
        },
        {
            name: 'data',
            type: 'mixed'
        },
        {
            name: 'extensions',
            type: 'array',
            optional: true
        }
    ],

    handler(command, callback) {
        // Check if FETCH method is set
        if (typeof this._server.onFetch !== 'function') {
            return callback(null, {
                response: 'NO',
                message: command.command + ' not implemented'
            });
        }

        let isUid = (command.command || '').toString().toUpperCase() === 'UID FETCH' ? true : false;
        let range = (command.attributes[0] && command.attributes[0].value) || '';
        if (!imapTools.validateSequnce(range)) {
            return callback(new Error('Invalid sequence set for ' + command.command));
        }
        let messages = imapTools.getMessageRange(this.selected.uidList, range, isUid);
        let flagsExist = false;
        let uidExist = false;
        let modseqExist = false;
        let bodystructureExist = false;
        let rfc822sizeExist = false;
        let idateExist = false;
        let envelopeExist = false;
        let markAsSeen = false;
        let metadataOnly = true;
        let changedSince = 0;
        let query = [];

        let params = [].concat(command.attributes[1] || []);
        let extensions = [].concat(command.attributes[2] || []).map(val => val && val.value);

        if (extensions.length) {
            if (extensions.length !== 2 || (extensions[0] || '').toString().toUpperCase() !== 'CHANGEDSINCE' || isNaN(extensions[1])) {
                return callback(new Error('Invalid modifier for ' + command.command));
            }
            changedSince = Number(extensions[1]);
            if (changedSince && !this.selected.condstoreEnabled) {
                this.condstoreEnabled = this.selected.condstoreEnabled = true;
            }
        }

        let macros = new Map(
            // Map iterator is a list of tuples
            [
                // ALL
                ['ALL', ['FLAGS', 'INTERNALDATE', 'RFC822.SIZE', 'ENVELOPE']],
                // FAST
                ['FAST', ['FLAGS', 'INTERNALDATE', 'RFC822.SIZE']],
                // FULL
                ['FULL', ['FLAGS', 'INTERNALDATE', 'RFC822.SIZE', 'ENVELOPE', 'BODY']]
            ]
        );

        let i, len, param, section;

        // normalize query

        // replace macro with actual items
        if (command.attributes[1].type === 'ATOM' && macros.has(command.attributes[1].value.toUpperCase())) {
            params = macros.get(command.attributes[1].value.toUpperCase());
        }

        // checks conditions – does the messages need to be marked as seen, is the full body needed etc.
        for (i = 0, len = params.length; i < len; i++) {
            param = params[i];
            if (!param || (typeof param !== 'string' && param.type !== 'ATOM')) {
                return callback(new Error('Invalid message data item name for ' + command.command));
            }

            if (typeof param === 'string') {
                param = params[i] = {
                    type: 'ATOM',
                    value: param
                };
            }

            if (param.value.toUpperCase() === 'FLAGS') {
                flagsExist = true;
            }

            if (param.value.toUpperCase() === 'UID') {
                uidExist = true;
            }

            if (param.value.toUpperCase() === 'MODSEQ') {
                modseqExist = true;
            }

            if (param.value.toUpperCase() === 'BODYSTRUCTURE') {
                bodystructureExist = true;
            }

            if (param.value.toUpperCase() === 'RFC822.SIZE') {
                rfc822sizeExist = true;
            }

            if (param.value.toUpperCase() === 'ENVELOPE') {
                envelopeExist = true;
            }

            if (param.value.toUpperCase() === 'INTERNALDATE') {
                idateExist = true;
            }

            if (!this.selected.readOnly) {
                if (param.value.toUpperCase() === 'BODY' && param.section) {
                    // BODY[...]
                    markAsSeen = true;
                } else if (param.value.toUpperCase() === 'RFC822') {
                    // RFC822
                    markAsSeen = true;
                }
            }

            if (param.value.toUpperCase() === 'BODY.PEEK' && param.section) {
                param.value = 'BODY';
            }

            if (['BODY', 'RFC822', 'RFC822.HEADER', 'RFC822.TEXT'].indexOf(param.value.toUpperCase()) >= 0) {
                metadataOnly = false;
            }
        }

        // Adds FLAGS to the response if needed. If the query touches BODY[] then this message
        // must be marked as \Seen. To inform the client about flags change, include the updated
        // flags in the response
        if (markAsSeen && !flagsExist) {
            params.push({
                type: 'ATOM',
                value: 'FLAGS'
            });
            flagsExist = true;
        }

        // ensure UID is listed if the command is UID FETCH
        if (isUid && !uidExist) {
            params.push({
                type: 'ATOM',
                value: 'UID'
            });
        }

        // ensure MODSEQ is listed if the command uses CHANGEDSINCE modifier
        if (changedSince && !modseqExist) {
            params.push({
                type: 'ATOM',
                value: 'MODSEQ'
            });
        }

        // returns header field name from a IMAP command object
        let getFieldName = field => (field.value || '').toString().toLowerCase();

        // compose query object from parsed IMAP command
        for (i = 0, len = params.length; i < len; i++) {
            param = params[i];
            let item = {
                query: imapHandler.compiler({
                    attributes: param
                }),
                item: (param.value || '').toString().toLowerCase(),
                original: param
            };

            if (param.section) {
                if (!param.section.length) {
                    item.path = '';
                    item.type = 'content';
                } else {
                    // we are expecting stuff like 'TEXT' or '1.2.3.TEXT' or '1.2.3'
                    // the numeric part ('1.2.3') is the path to the MIME node
                    // and 'TEXT' or '' is the queried item (empty means entire content)
                    section = (param.section[0].value || '').toString().toLowerCase();
                    item.path = section.match(/^(\d+\.)*(\d+$)?/);

                    if (item.path && item.path[0].length) {
                        item.path = item.path[0].replace(/\.$/, '');
                        item.type = section.substr(item.path.length + 1) || 'content';
                    } else {
                        item.path = isNaN(section) ? '' : section;
                        item.type = section;
                    }

                    /*
                    item.type = (param.section[0].value || '').toString().toLowerCase();
                    */
                    if (/^HEADER.FIELDS(\.NOT)?$/i.test(item.type) && Array.isArray(param.section[1])) {
                        item.headers = param.section[1].map(getFieldName);
                    }
                }
                // return this element as literal value
                item.isLiteral = true;
            }

            if (['RFC822', 'RFC822.HEADER', 'RFC822.TEXT'].indexOf(param.value.toUpperCase()) >= 0) {
                item.isLiteral = true;
            }

            if (param.partial) {
                item.partial = {
                    startFrom: Number(param.partial[0]) || 0,
                    maxLength: Number(param.partial[1]) || 0
                };

                if (item.partial.maxLength && item.partial.maxLength < 1024 * 1024) {
                    //item.partial.maxLength = 1024 * 1024;
                }
            }
            if (!imapTools.fetchSchema.hasOwnProperty(item.item) || !checkSchema(imapTools.fetchSchema[item.item], item)) {
                return callback(null, {
                    response: 'BAD',
                    message: 'Invalid message data item ' + item.query + ' for ' + command.command
                });
            }

            query.push(item);
        }

        this._server.logger.debug(
            {
                tnx: 'fetch',
                cid: this.id
            },
            'FETCH: %s',
            JSON.stringify({
                metadataOnly: !!metadataOnly,
                markAsSeen: !!markAsSeen,
                messages: messages.length,
                query,
                changedSince,
                isUid
            })
        );

        let startTime = Date.now();
        let logdata = {
            short_message: '[FETCH]',
            _mail_action: 'fetch',
            _user: this.session.user.id.toString(),
            _mailbox: this.selected.mailbox.toString(),
            _sess: this.id,
            _mark_seen: markAsSeen ? 'yes' : 'no',
            _is_uid: isUid ? 'yes' : 'no',
            _message_count: messages.length,
            _modseq: changedSince,
            _query: imapHandler.compiler(command)
        };

        this._server.onFetch(
            this.selected.mailbox,
            {
                bodystructureExist,
                rfc822sizeExist,
                envelopeExist,
                flagsExist,
                idateExist,
                metadataOnly: !!metadataOnly,
                markAsSeen: !!markAsSeen,
                messages,
                query,
                changedSince,
                isUid
            },
            this.session,
            (err, success, info) => {
                logdata._query_time = Date.now() - startTime;

                Object.keys(info || {}).forEach(key => {
                    let vkey = '_' + key.replace(/[A-Z]+/g, c => '_' + c.toLowerCase());
                    if (vkey === '_id') {
                        vkey = '_fetch_id';
                    }
                    logdata[vkey] = info[key];
                });

                if (err) {
                    logdata._error = err.message;
                    logdata._code = err.code;
                    logdata._response = err.response;
                    logdata._responseMessage = err.responseMessage;
                    logdata._ratelimit_ttl = err.ttl;
                    this._server.loggelf(logdata);

                    return callback(null, {
                        response: 'NO',
                        code: 'TEMPFAIL',
                        message: err.responseMessage
                    });
                }

                logdata._response = success;
                this._server.loggelf(logdata);

                callback(null, {
                    response: success === true ? 'OK' : 'NO',
                    code: typeof success === 'string' ? success.toUpperCase() : false
                });
            }
        );
    }
};

function checkSchema(schema, item) {
    let i, len;
    if (Array.isArray(schema)) {
        for (i = 0, len = schema.length; i < len; i++) {
            if (checkSchema(schema[i], item)) {
                return true;
            }
        }
        return false;
    }

    if (schema === true) {
        if (item.hasOwnProperty('type') || item.partial) {
            return false;
        }
        return true;
    }

    if (typeof schema === 'object' && schema) {
        // check.type
        switch (Object.prototype.toString.call(schema.type)) {
            case '[object RegExp]':
                if (!schema.type.test(item.type)) {
                    return false;
                }
                break;
            case '[object String]':
                if (schema.type !== item.type) {
                    return false;
                }
                break;
            case '[object Boolean]':
                if (item.hasOwnProperty('type') || item.partial || schema.type !== true) {
                    return false;
                }
                break;
            default:
                return false;
        }

        // check if headers must be present
        if (schema.headers && schema.headers.test(item.type) && !Array.isArray(item.headers)) {
            return false;
        }

        return true;
    }

    return false;
}
