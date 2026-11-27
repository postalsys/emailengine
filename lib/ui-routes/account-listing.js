'use strict';

// The admin accounts list's filters: the query it accepts, the pills it shows and the count in the
// page header. The listing itself is Account#listAccounts(), shared with GET /v1/accounts.

const Joi = require('joi');

const { accountListingSchemas } = require('../schemas');
const { DEFAULT_PAGE_SIZE } = require('../consts');
const { availableAccountKinds } = require('../account/listing-filters');
const { ACCOUNT_STATE_DISPLAY } = require('./route-helpers');
const { listPageView, multiValue } = require('./list-filters');

// "Needs attention" first: it is the view the dashboard links to and the one most visits want
const STATE_OPTIONS = [{ value: 'errors', label: 'Needs attention' }, ...ACCOUNT_STATE_DISPLAY.map(({ state, label }) => ({ value: state, label }))];

const accountListQuerySchema = Joi.object({
    page: Joi.number().integer().min(1).max(1000000).default(1),
    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE),
    query: Joi.string().trim().empty('').max(256).example('user@example.com').description('Filter accounts by name/email match').label('AccountQuery'),
    // "errors" stands for every attention state
    state: multiValue(STATE_OPTIONS).description('Filter accounts by states, "errors" for every attention state'),
    domain: accountListingSchemas.domain,
    type: accountListingSchemas.type.default([])
});

/**
 * The listing's filter bar and the URLs that keep the current filters.
 *
 * @param {Object} current - The validated list query
 * @param {Array<Object>} apps - The instance's OAuth2 apps, which decide the kinds offered
 * @param {Object} data - The listing, for the page links
 * @returns {Object} See listPageView()
 */
function accountListView(current, apps, data) {
    return listPageView({
        path: '/admin/accounts',
        current,
        data,
        filters: [
            { name: 'state', label: 'Status', type: 'multi', options: STATE_OPTIONS },
            { name: 'type', label: 'Type', type: 'multi', options: availableAccountKinds(apps) },
            { name: 'domain', label: 'Domain', type: 'text', placeholder: 'example.com', hint: 'Subdomains match too.' }
        ]
    });
}

/**
 * The page header count: the matches, and the whole when a filter or search narrows it.
 *
 * @param {Number} matching - Accounts the listing matched
 * @param {Number} total - Accounts on the instance
 * @param {Boolean} narrowed - Whether a filter or search applies
 * @returns {String}
 */
function accountCountLabel(matching, total, narrowed) {
    return narrowed ? `${matching} of ${total}` : String(total);
}

module.exports = { accountListQuerySchema, accountListView, accountCountLabel };
