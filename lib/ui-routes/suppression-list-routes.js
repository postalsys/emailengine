'use strict';

// Admin UI for suppression lists (the store behind the Blocklists API and the public
// unsubscribe flow): /admin/suppression-lists (listing + add/delete) and
// /admin/suppression-lists/list/{listId} (entries + per-address removal). Lists are
// registered ad hoc, so adding an address to an unknown list ID creates that list, and
// removing the last address drops the list again (see lib/lua/ee-list-remove.lua).

const Joi = require('joi');
const { lists } = require('../lists');
const settings = require('../settings');
const { blocklistListIdSchema } = require('../schemas');
const { buildPagingView, resolveKnownAccounts, adminUrl } = require('./route-helpers');
const { buildUnsubscribeUrl, getServiceSecret } = require('../tools');
const consts = require('../consts');

const { DEFAULT_PAGE_SIZE } = consts;

const pagingQuerySchema = Joi.object({
    page: Joi.number().integer().min(1).max(1000000).default(1),
    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
});

function init(args) {
    const { server } = args;

    server.route({
        method: 'GET',
        path: '/admin/suppression-lists',
        async handler(request, h) {
            let data = await lists.list(request.query.page - 1, request.query.pageSize);

            return h.view(
                'suppression-lists/index',
                {
                    pageTitle: 'Suppression Lists',
                    menuSuppressionLists: true,

                    total: data.total,

                    ...buildPagingView('admin/suppression-lists', data, request.query),

                    suppressionLists: data.blocklists
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/suppression-lists').takeover();
                },

                query: pagingQuerySchema
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/suppression-lists/list/{listId}',
        async handler(request, h) {
            let listId = request.params.listId;

            let data;
            try {
                data = await lists.listContent(listId, request.query.page - 1, request.query.pageSize);
            } catch (err) {
                // Only a missing list reads as one. Anything else (say, a dropped Redis
                // connection) is a transient failure of an intact list - reporting it as
                // "not found" tells the operator their unsubscribe data is gone when it is not.
                if (err.output && err.output.statusCode === 404) {
                    await request.flash({ type: 'danger', message: `Requested suppression list was not found` });
                } else {
                    request.logger.error({ msg: 'Failed to load suppression list', listId, err });
                    await request.flash({ type: 'danger', message: `Failed to load the suppression list. Try again.` });
                }
                return h.redirect('/admin/suppression-lists');
            }

            // Link each entry to its public subscription management page - the same signed URL
            // the List-Unsubscribe header carries - so the page can be previewed or the link
            // sent to the recipient for self service re-subscription. The page loads the
            // account, so entries without one (or whose account is gone) get no link.
            let [serviceUrl, serviceSecret] = await Promise.all([settings.get('serviceUrl'), getServiceSecret()]);

            let knownAccounts = await resolveKnownAccounts(data.addresses);

            for (let entry of data.addresses) {
                if (!entry.account || !knownAccounts.get(entry.account)) {
                    continue;
                }
                entry.unsubscribeUrl = buildUnsubscribeUrl(serviceSecret, serviceUrl, {
                    account: entry.account,
                    list: listId,
                    recipient: entry.recipient
                });
            }

            return h.view(
                'suppression-lists/list',
                {
                    pageTitle: `Suppression Lists - ${listId}`,
                    menuSuppressionLists: true,

                    listId,
                    total: data.total,

                    ...buildPagingView(`admin/suppression-lists/list/${listId}`, data, request.query),

                    addresses: data.addresses
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/suppression-lists').takeover();
                },

                params: Joi.object({
                    listId: blocklistListIdSchema
                }),

                query: pagingQuerySchema
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/suppression-lists/add',
        async handler(request, h) {
            let { listId, recipient, reason } = request.payload;

            try {
                let added = await lists.add(listId, recipient, {
                    source: 'admin',
                    reason,
                    remoteAddress: request.app.ip,
                    userAgent: request.headers['user-agent']
                });

                if (added) {
                    await request.flash({ type: 'info', message: `Added ${recipient} to the suppression list` });
                } else {
                    await request.flash({ type: 'info', message: `${recipient} was already listed; the entry was updated` });
                }

                return h.redirect(adminUrl`/admin/suppression-lists/list/${listId}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't add the address. Try again.` });
                request.logger.error({ msg: 'Failed to add suppression list entry', err, listId, remoteAddress: request.app.ip });
                return h.redirect('/admin/suppression-lists');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't add the address. Check the list ID and email address and try again.` });
                    request.logger.error({ msg: 'Failed to add suppression list entry', err });

                    return h.redirect('/admin/suppression-lists').takeover();
                },

                payload: Joi.object({
                    listId: blocklistListIdSchema,
                    recipient: Joi.string().empty('').email().required().description('Email address to suppress'),
                    reason: Joi.string().empty('').max(256).default('block').description('Identifier for the blocking reason')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/suppression-lists/list/{listId}/remove',
        async handler(request, h) {
            let listId = request.params.listId;
            let recipient = request.payload.recipient;

            try {
                let removed = await lists.remove(listId, recipient);

                if (!removed) {
                    await request.flash({ type: 'danger', message: `${recipient} was not found on the list` });
                } else if (!(await lists.exists(listId))) {
                    // removing the final address drops the list itself
                    await request.flash({ type: 'info', message: `Removed ${recipient}; the now empty list was deleted` });
                    return h.redirect('/admin/suppression-lists');
                } else {
                    await request.flash({ type: 'info', message: `Removed ${recipient} from the suppression list` });
                }

                return h.redirect(adminUrl`/admin/suppression-lists/list/${listId}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't remove the address. Try again.` });
                request.logger.error({ msg: 'Failed to remove suppression list entry', err, listId, remoteAddress: request.app.ip });
                return h.redirect(adminUrl`/admin/suppression-lists/list/${listId}`);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't remove the address. Try again.` });
                    request.logger.error({ msg: 'Failed to remove suppression list entry', err });

                    return h.redirect('/admin/suppression-lists').takeover();
                },

                params: Joi.object({
                    listId: blocklistListIdSchema
                }),

                payload: Joi.object({
                    // entry keys are stored normalized, but accept whatever was displayed
                    recipient: Joi.string().max(1024).required().description('Listed address to remove')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/suppression-lists/delete',
        async handler(request, h) {
            let listId = request.payload.listId;

            try {
                let deleted = await lists.deleteList(listId);

                if (deleted) {
                    await request.flash({ type: 'info', message: `Suppression list deleted` });
                } else {
                    await request.flash({ type: 'danger', message: `Requested suppression list was not found` });
                }

                return h.redirect('/admin/suppression-lists');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't delete the suppression list. Try again.` });
                request.logger.error({ msg: 'Failed to delete suppression list', err, listId, remoteAddress: request.app.ip });
                return h.redirect('/admin/suppression-lists');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't delete the suppression list. Try again.` });
                    request.logger.error({ msg: 'Failed to delete suppression list', err });

                    return h.redirect('/admin/suppression-lists').takeover();
                },

                payload: Joi.object({
                    listId: blocklistListIdSchema
                })
            }
        }
    });
}

module.exports = init;
