'use strict';

// Readers for whole-number settings and environment values. Dependency-free, so pure modules can
// share them: the overridable settings, the token audit log and the webhook retry policy each had
// a parser of their own, and they disagreed on blank values, zero and fractions.

/**
 * A whole number of at least 1, or undefined for anything else. Fractions are floored.
 * @param {*} value
 * @returns {number|undefined}
 */
function asPositiveInt(value) {
    const parsed = Math.floor(Number(value));
    return Number.isFinite(parsed) && parsed >= 1 ? parsed : undefined;
}

/**
 * A whole number of at least 0, or undefined for anything else, blank values included (Number('')
 * would read as 0). Fractions are floored.
 * @param {*} value
 * @returns {number|undefined}
 */
function asNonNegativeInt(value) {
    if (value === '' || value === null || value === undefined) {
        return undefined;
    }
    const parsed = Math.floor(Number(value));
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

/**
 * A whole number clamped into [min, max], or the default for anything that is not one: a setting
 * that is unset, cleared, or written by an older version without validation
 * @param {*} value
 * @param {number} defaultValue
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function boundedInt(value, defaultValue, min, max) {
    const number = Number(value);
    if (value === null || value === undefined || value === '' || !Number.isInteger(number)) {
        return defaultValue;
    }
    return Math.min(Math.max(number, min), max);
}

module.exports = { asPositiveInt, asNonNegativeInt, boundedInt };
