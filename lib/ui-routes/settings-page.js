'use strict';

// Shared GET/POST registration for the admin settings-form pages (/admin/config/*).
//
// Each of these pages used to hand-copy its view context into three render paths
// (GET, POST catch, POST validation failAction). The copies drifted more than once
// (stale menu flags highlighting the wrong sidebar item on validation errors), and
// both error paths dropped the submitted values, so a failed save cleared the form
// back to the stored settings. This helper builds the context in one place and
// re-renders the submitted payload on both error paths.
//
// Page definition:
//   path           - route path, also the redirect target after a successful save
//   view           - handlebars view name
//   pageTitle      - browser/page title
//   menuKey        - leaf menu flag (menuConfigXxx); menuConfig is always set
//   schema         - Joi schema map for the POST payload
//   loadValues     - async (request) => values for the GET render
//   applySettings  - async (request) => persist request.payload; may throw with
//                    err.details ({ field: message }) to surface field errors
//   errorValues    - optional async (request) => values for error re-renders;
//                    defaults to the submitted payload as-is
//   viewContext    - optional async (request, values, h) => extra view context,
//                    shared verbatim by all three render paths

const Joi = require('joi');

function registerSettingsPage(server, page) {
    const { path, view, pageTitle, menuKey, schema, loadValues, applySettings, errorValues, viewContext } = page;

    const buildContext = async (request, h, values, errors) => {
        let context = { pageTitle, menuConfig: true };
        context[menuKey] = true;
        Object.assign(context, viewContext ? await viewContext(request, values, h) : {}, { values });
        if (errors) {
            context.errors = errors;
        }
        return context;
    };

    server.route({
        method: 'GET',
        path,
        async handler(request, h) {
            const values = await loadValues(request);
            return h.view(view, await buildContext(request, h, values), { layout: 'app' });
        }
    });

    // Error re-renders show what was submitted, not the stored settings, so a failed
    // save does not clear the operator's input. On validation failures request.payload
    // is the raw parsed form (strings, 'on' checkboxes); on write failures it is the
    // validated payload - the templates handle both.
    const renderError = async (request, h, errors) => {
        const values = errorValues ? await errorValues(request) : request.payload;
        return h.view(view, await buildContext(request, h, values, errors), { layout: 'app' });
    };

    server.route({
        method: 'POST',
        path,
        async handler(request, h) {
            try {
                await applySettings(request);

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect(path);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                return await renderError(request, h, err.details);
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
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    return (await renderError(request, h, errors)).takeover();
                },

                payload: Joi.object(schema)
            }
        }
    });
}

module.exports = { registerSettingsPage };
