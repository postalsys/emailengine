'use strict';

// View model for the filter pills above an admin list (views/partials/ui/filter-bar.hbs and the
// filter-bar behavior in static/js/ui.js). A list page describes its filters once; this turns the
// validated query into the pills, the links that drop one filter or all of them, and the hidden
// inputs that carry the filters through the topbar search.
//
// Filter values live in the query string only. Nothing is remembered between visits, so opening a
// list from the menu always shows all of it, and every filtered view is a link.

/**
 * A list URL with the given parameters. Arrays repeat their key; empty values are left out.
 *
 * @param {String} path - The list path, e.g. "/admin/accounts"
 * @param {Object} params - Parameter values (strings, numbers or arrays of them)
 * @returns {String} Path and query string
 */
function listUrl(path, params) {
    const search = new URLSearchParams();
    for (const [key, value] of Object.entries(params || {})) {
        for (const entry of [].concat(value === undefined || value === null || value === false ? [] : value)) {
            if (entry !== '' && entry !== undefined && entry !== null) {
                search.append(key, String(entry));
            }
        }
    }
    const query = search.toString();
    return query ? `${path}?${query}` : path;
}

// { name: value | [values] } as hidden inputs, one per value
function toHiddenInputs(params) {
    return Object.entries(params).flatMap(([name, value]) => [].concat(value).map(entry => ({ name, value: entry })));
}

function hasValue(value) {
    return Array.isArray(value) ? value.length > 0 : value !== undefined && value !== null && value !== '';
}

// "Connected", "Connected, Paused", "Connected +2"
function summarizeChoices(labels) {
    if (labels.length <= 2) {
        return labels.join(', ');
    }
    return `${labels[0]} +${labels.length - 1}`;
}

function buildPill(filter, current, dropFilter) {
    const value = current[filter.name];
    const pill = {
        id: `filter-${filter.name}`,
        name: filter.name,
        label: filter.label,
        active: hasValue(value),
        clearHref: dropFilter(filter.name)
    };

    if (filter.type === 'text' || filter.type === 'account') {
        Object.assign(pill, {
            isText: filter.type === 'text',
            isAccount: filter.type === 'account',
            value: pill.active ? value : '',
            placeholder: filter.placeholder || '',
            hint: filter.hint || '',
            // the account picker's entry for the chosen account
            selected: filter.selected || null,
            summary: pill.active ? filter.summary || value : ''
        });
        return pill;
    }

    const selected = [].concat(value || []);
    const options = (filter.options || []).map(option => Object.assign({ checked: selected.includes(option.value) }, option));
    // A value no longer offered (an app was removed, a link from elsewhere) still shows, so it can
    // be seen and cleared
    for (const entry of selected) {
        if (!options.some(option => option.value === entry)) {
            options.push({ value: entry, label: entry, checked: true });
        }
    }

    pill.isMulti = true;
    pill.options = options;
    pill.summary = summarizeChoices(options.filter(option => option.checked).map(option => option.label));
    return pill;
}

/**
 * Builds the filter bar for a list page.
 *
 * @param {Object} opts
 * @param {String} opts.path - The list path the bar submits to
 * @param {Object} opts.current - The validated list query
 * @param {Array<String>} [opts.keep] - Query keys a filter change keeps (the search, the page
 *   size); the page number is never kept, a changed filter starts on page one
 * @param {Array<Object>} opts.filters - `{ name, label, type: 'multi' | 'text' | 'account',
 *   options: [{ value, label }], placeholder, hint, summary }`
 * @returns {Object} `{ action, hidden, pills, active, clearHref, searchHidden }`
 */
function buildFilterBar({ path, current, keep = [], filters }) {
    const kept = {};
    for (const key of keep) {
        if (hasValue(current[key])) {
            kept[key] = current[key];
        }
    }

    const filterValues = {};
    for (const filter of filters) {
        if (hasValue(current[filter.name])) {
            filterValues[filter.name] = current[filter.name];
        }
    }

    const dropFilter = name => listUrl(path, Object.assign({}, kept, filterValues, { [name]: null }));

    const pills = filters.map(filter => buildPill(filter, current, dropFilter));
    const active = pills.some(pill => pill.active);

    const { query: _search, ...keptBesidesSearch } = kept;

    return {
        action: path,
        // The pills form carries what a filter change keeps
        hidden: toHiddenInputs(kept),
        pills,
        active,
        clearHref: listUrl(path, kept),
        // The topbar search form carries the filters (and the page size), not the search it replaces
        searchHidden: toHiddenInputs(Object.assign({}, keptBesidesSearch, filterValues))
    };
}

module.exports = { buildFilterBar, listUrl };
