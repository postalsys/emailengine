'use strict';

// The Handlebars helpers the admin views render with. Registered on the shared handlebars
// instance by workers/api.js at startup; kept apart from the worker so a test can register
// the same helpers and render a template that relies on them (the delivery-test fragment in
// lib/ui-routes/route-helpers.js is compiled with this instance too).

const util = require('util');

/**
 * Registers every view helper on the given handlebars instance.
 *
 * @param {Object} handlebars - The handlebars module instance vision renders with
 * @param {Object} options
 * @param {Object} options.gt - Gettext instance for the translation helpers
 */
function registerHandlebarsHelpers(handlebars, { gt }) {
    handlebars.registerHelper('_', (...args) => {
        let params = args.slice(1, args.length - 1);

        let locale = params.shift();

        let localGt = locale ? gt.useLocale(locale) : gt;

        let translated = localGt.gettext(args[0]);
        if (params.length) {
            translated = util.format(translated, ...params);
        }

        return new handlebars.SafeString(translated);
    });

    // HTML-escape a value for safe interpolation into an otherwise-unescaped context - e.g. a
    // dynamic `%s` argument to the SafeString-returning `_` helper. Returns a plain string so
    // the surrounding markup stays live while the value itself is entity-escaped.
    handlebars.registerHelper('escapeHtml', value => handlebars.escapeExpression(value));

    // Translate Bootstrap-era color names emitted by server code (flash types,
    // systemAlerts levels) into the FlyonUI color vocabulary used by the admin
    // theme, so templates interpolate a single closed set of class suffixes
    // (which the stylesheet safelists). Single translation point - producers
    // keep using "danger" etc.
    handlebars.registerHelper('eeColor', value => (value === 'danger' ? 'error' : value || 'neutral'));

    // Percent-encode a value for interpolation into a URL path segment. Handlebars escapes for
    // HTML, which leaves "#", "/", "?" and "%" untouched - and an account ID is free text, so
    // href="/admin/accounts/{{account}}" resolves somewhere else entirely for an ID carrying one.
    handlebars.registerHelper('urlpart', value => encodeURIComponent(value === null || value === undefined ? '' : value));

    // Join string fragments in subexpressions, e.g. building composed partial
    // hash values: text=(concat "Up to " (formatInteger n locale) " lines")
    handlebars.registerHelper('concat', (...args) => args.slice(0, -1).join(''));

    // Ternary for subexpressions: placeholder=(when hasPass "set..." "")
    handlebars.registerHelper('when', (cond, truthyValue, falsyValue) => (cond ? truthyValue : typeof falsyValue === 'string' ? falsyValue : ''));

    handlebars.registerHelper('isodate', time => new Date(Number(time)).toISOString());

    handlebars.registerHelper('ngettext', (msgid, plural, count) => util.format(gt.ngettext(msgid, plural, count), count));

    handlebars.registerHelper('equals', function (compareVal, baseVal, options) {
        if (baseVal === compareVal) {
            return options.fn(this);
        }
        return options.inverse(this);
    });

    handlebars.registerHelper('inc', (nr, inc) => Number(nr) + Number(inc));

    // Delivery-test verdict (SPF/DKIM/DMARC status.result) to the FlyonUI color and icon the
    // results fragment (views/partials/test_send.hbs) shows next to each check
    const STATUS_COLORS = { pass: 'success', softfail: 'warning', fail: 'error', permerror: 'info', temperror: 'info' };
    handlebars.registerHelper('statusColor', result => STATUS_COLORS[result] || 'neutral');

    handlebars.registerHelper('statusIcon', result => {
        switch (result) {
            case 'pass':
                return 'icon-[tabler--circle-check]';
            case 'neutral':
            case 'none':
                return 'icon-[tabler--circle-off]';
            default:
                return 'icon-[tabler--alert-triangle]';
        }
    });

    handlebars.registerHelper('json', payload => {
        let res;
        try {
            res = typeof payload === 'undefined' ? 'undefined' : JSON.stringify(payload, false, 2);
        } catch (err) {
            res = util.inspect(payload, false, 4, false);
        }
        // SECURITY: return a plain string (NOT a SafeString) so Handlebars HTML-escapes the
        // output. `payload` can carry attacker-controlled data (e.g. inbound email fields in
        // webhook / pre-processing error logs); wrapping it in a SafeString allowed a stored
        // XSS via a </textarea> breakout in the error-log views (security review H1). In the
        // <textarea> render contexts this is display-identical (the browser decodes entities).
        return res;
    });

    handlebars.registerHelper('lastVal', (value, separator) => {
        separator = separator || '/';

        let res = (value || '').toString().split(separator).pop();

        return new handlebars.SafeString(res);
    });

    handlebars.registerHelper('formatInteger', (intVal, locale) => {
        if (isNaN(intVal)) {
            // ignore non-numbers
            return intVal;
        }

        locale = (locale || 'en_US').replace(/_/g, '-');

        let formatter;
        try {
            formatter = new Intl.NumberFormat(locale, {});
        } catch (err) {
            formatter = new Intl.NumberFormat('en-US', {});
        }

        return formatter.format(intVal);
    });
}

module.exports = { registerHandlebarsHelpers };
