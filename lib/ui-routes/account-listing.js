'use strict';

// The admin accounts list's filters: the query it accepts, the pills it shows and the count in the
// page header. The listing itself is Account#listAccounts(), shared with GET /v1/accounts.

const Joi = require('joi');

const { ACCOUNT_DISPLAY_STATES, accountListingSchemas } = require('../schemas');
const { DEFAULT_PAGE_SIZE } = require('../consts');
const { availableAccountKinds } = require('../account/listing-filters');
const { ACCOUNT_STATE_DISPLAY } = require('./route-helpers');
const { buildFilterBar, listUrl } = require('./list-filters');

const LIST_PATH = '/admin/accounts';

// "Needs attention" first: it is the view the dashboard links to and the one most visits want
const STATE_OPTIONS = [{ value: 'errors', label: 'Needs attention' }, ...ACCOUNT_STATE_DISPLAY.map(({ state, label }) => ({ value: state, label }))];

const accountListQuerySchema = Joi.object({
    page: Joi.number().integer().min(1).max(1000000).default(1),
    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE),
    query: Joi.string().trim().empty('').max(256).example('user@example.com').description('Filter accounts by name/email match').label('AccountQuery'),
    state: Joi.array()
        .items(
            Joi.string()
                .trim()
                .valid(...ACCOUNT_DISPLAY_STATES, 'errors')
        )
        .single()
        .default([])
        .description('Filter accounts by states, "errors" for every attention state'),
    domain: accountListingSchemas.domain,
    type: accountListingSchemas.type.default([])
});

/**
 * The listing's filter bar and the URLs that keep the current filters.
 *
 * @param {Object} current - The validated list query
 * @param {Array<Object>} apps - The instance's OAuth2 apps, which decide the kinds offered
 * @returns {Object} `{ filterBar, pageUrl }`
 */
function accountListView(current, apps) {
    // the default page size stays out of every URL
    const pageSize = current.pageSize !== DEFAULT_PAGE_SIZE ? current.pageSize : null;

    const filterBar = buildFilterBar({
        path: LIST_PATH,
        current: Object.assign({}, current, { pageSize }),
        keep: ['query', 'pageSize'],
        filters: [
            { name: 'state', label: 'Status', type: 'multi', options: STATE_OPTIONS },
            { name: 'type', label: 'Type', type: 'multi', options: availableAccountKinds(apps) },
            {
                name: 'domain',
                label: 'Domain',
                type: 'text',
                placeholder: 'example.com',
                hint: 'Subdomains match too.'
            }
        ]
    });

    const params = {
        pageSize,
        query: current.query,
        state: current.state,
        type: current.type,
        domain: current.domain
    };

    const pageUrl = page => listUrl(LIST_PATH, Object.assign({ page: page > 1 ? page : null }, params));

    // The search crumb and "Clear search" drop the search and keep the filters
    const clearSearchHref = listUrl(LIST_PATH, Object.assign({}, params, { query: null }));

    return { filterBar, pageUrl, clearSearchHref };
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
