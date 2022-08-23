'use strict';

const imapHandler = require('../handler/imap-handler');
const imapTools = require('../imap-tools');

module.exports = {
    state: 'Selected',

    schema: false, // recursive, can't predefine

    handler(command, callback) {
        // Check if SEARCH method is set
        if (typeof this._server.onSearch !== 'function') {
            return callback(null, {
                response: 'NO',
                message: command.command + ' not implemented'
            });
        }

        let isUid = (command.command || '').toString().toUpperCase() === 'UID SEARCH' ? true : false;

        let terms = [];
        let getTerms = elements => {
            elements.forEach(element => {
                if (Array.isArray(element)) {
                    return getTerms(element);
                }
                terms.push(element.value);
            });
        };
        getTerms([].concat(command.attributes || []));

        let parsed;

        try {
            parsed = parseQueryTerms(terms, this.selected.uidList);
        } catch (E) {
            return callback(E);
        }

        // mark CONDSTORE as enabled
        if (parsed.terms.indexOf('modseq') >= 0 && !this.selected.condstoreEnabled) {
            this.condstoreEnabled = this.selected.condstoreEnabled = true;
        }

        let logdata = {
            short_message: '[SEARCH]',
            _mail_action: 'search',
            _user: this.session.user.id.toString(),
            _mailbox: this.selected.mailbox,
            _sess: this.id,
            _query: JSON.stringify(parsed.query),
            _terms: JSON.stringify(parsed.terms)
        };
        this._server.onSearch(
            this.selected.mailbox,
            {
                query: parsed.query,
                terms: parsed.terms,
                isUid
            },
            this.session,
            (err, results) => {
                if (err) {
                    logdata._error = err.message;
                    logdata._code = err.code;
                    logdata._response = err.response;
                    this._server.loggelf(logdata);
                    return callback(null, {
                        response: 'NO',
                        code: 'TEMPFAIL'
                    });
                }

                let matches = results.uidList;

                if (typeof matches === 'string') {
                    return callback(null, {
                        response: 'NO',
                        code: matches.toUpperCase()
                    });
                }

                let response = {
                    tag: '*',
                    command: 'SEARCH',
                    attributes: []
                };

                if (Array.isArray(matches) && matches.length) {
                    matches.sort((a, b) => a - b);

                    matches.forEach(nr => {
                        let seq;

                        if (!isUid) {
                            seq = this.selected.uidList.indexOf(nr) + 1;
                            if (seq) {
                                response.attributes.push({
                                    type: 'atom',
                                    value: String(seq)
                                });
                            }
                        } else {
                            response.attributes.push({
                                type: 'atom',
                                value: String(nr)
                            });
                        }
                    });
                }

                // append (MODSEQ 123) for queries that include MODSEQ criteria
                if (results.highestModseq && parsed.terms.indexOf('modseq') >= 0) {
                    response.attributes.push([
                        {
                            type: 'atom',
                            value: 'MODSEQ'
                        },
                        {
                            type: 'atom',
                            value: String(results.highestModseq)
                        }
                    ]);
                }

                this.send(imapHandler.compiler(response));

                return callback(null, {
                    response: 'OK'
                });
            }
        );
    },

    parseQueryTerms // expose for testing
};

function parseQueryTerms(terms, uidList) {
    terms = [].concat(terms || []);

    let pos = 0;
    let term;
    let returnTerms = [];
    let parsed = {
        terms: []
    };

    let getTerm = level => {
        level = level || 0;
        if (pos >= terms.length) {
            return undefined; // eslint-disable-line no-undefined
        }

        let term = terms[pos++];
        let termType = imapTools.searchSchema[term.toLowerCase()];
        let termCount = termType && termType.length;
        let curTerm = [term.toLowerCase()];

        // MODSEQ is special case as it includes 2 optional arguments
        // If the next argument is a number then there is only one argument,
        // otherwise there is 3 arguments
        if (curTerm[0] === 'modseq') {
            termType = isNaN(terms[pos]) ? termType[0] : termType[1];
            termCount = termType.length;
        }

        if (!termType) {
            // try if it is a sequence set
            if (imapTools.validateSequnce(term)) {
                // resolve sequence list to an array of UID values
                curTerm = ['uid', imapTools.getMessageRange(uidList, term, false)];
            } else {
                // no idea what the term is for
                throw new Error('Unknown search term ' + term.toUpperCase());
            }
        } else if (termCount) {
            for (let i = 0, len = termCount; i < len; i++) {
                if (termType[i] === 'expression') {
                    curTerm.push(getTerm(level + 1));
                } else if (termType[i] === 'sequence') {
                    if (!imapTools.validateSequnce(terms[pos])) {
                        throw new Error('Invalid sequence set for ' + term.toUpperCase());
                    }
                    // resolve sequence list to an array of UID values
                    curTerm.push(imapTools.getMessageRange(uidList, terms[pos++], true));
                } else {
                    curTerm.push(terms[pos++]);
                }
            }
        }

        if (imapTools.searchMapping.hasOwnProperty(curTerm[0])) {
            curTerm = normalizeTerm(curTerm, imapTools.searchMapping[curTerm[0]]);
        }

        // return multiple values at once, should be already formatted
        if (typeof curTerm[0] === 'object') {
            return curTerm;
        }

        // keep a list of used terms
        if (parsed.terms.indexOf(curTerm[0]) < 0) {
            parsed.terms.push(curTerm[0]);
        }

        let response = {
            key: curTerm[0]
        };

        switch (response.key) {
            case 'not':
                // make sure not is not an array, instead return several 'not' expressions
                response = [].concat(curTerm[1] || []).map(val => ({
                    key: 'not',
                    value: val
                }));

                if (response.length === 1) {
                    response = response[0];
                }

                break;

            case 'or':
                // ensure that value is alwas an array
                response.value = [].concat(curTerm.slice(1) || []);
                break;

            case 'header':
                response.header = (curTerm[1] || '').toString().toLowerCase();
                response.value = (curTerm[2] || '').toString(); // empty header value means that the header key must be present
                break;

            case 'date':
            case 'internaldate':
                {
                    let dateval = (curTerm[2] || '').toString();
                    if (!imapTools.validateSearchDate(dateval)) {
                        throw new Error('Invalid date argument for ' + term.toUpperCase());
                    }
                    response.operator = curTerm[1];
                    response.value = dateval;
                }
                break;

            case 'size':
                if (isNaN(curTerm[2])) {
                    throw new Error('Invalid size argument for ' + response.key);
                }
                response.operator = curTerm[1];
                response.value = Number(curTerm[2]) || 0;
                break;

            case 'modseq':
                if (isNaN(curTerm[curTerm.length - 1])) {
                    throw new Error('Invalid MODSEQ argument');
                }
                response.value = Number(curTerm[curTerm.length - 1]) || 0;
                break;

            default:
                if (curTerm.length) {
                    response.value = curTerm.length > 2 ? curTerm.slice(1) : curTerm[1];
                }
        }

        return response;
    };

    while (typeof (term = getTerm()) !== 'undefined') {
        if (Array.isArray(term)) {
            // flatten arrays
            returnTerms = returnTerms.concat(term);
        } else {
            returnTerms.push(term);
        }
    }

    parsed.terms.sort();
    parsed.query = returnTerms;

    return parsed;
}

function normalizeTerm(term, mapping) {
    let flags;

    let result = [mapping.key].concat(mapping.value.map(val => (val === '$1' ? term[1] : val)));

    if (result[0] === 'flag') {
        flags = [];
        result.forEach((val, i) => {
            if (i && i % 2 !== 0) {
                flags.push({
                    key: 'flag',
                    value: val,
                    exists: !!result[i + 1]
                });
            }
        });
        return flags;
    }

    return result;
}
