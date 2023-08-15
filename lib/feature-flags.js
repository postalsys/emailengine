'use strict';

const FEATURES = new Set();

const ENABLED_FEATURES = [];

const formatFeatureKey = key =>
    (key || '')
        .toString()
        .trim()
        .toLowerCase()
        .replace(/[-_\s]+/g, '_');

for (let feature of ENABLED_FEATURES) {
    FEATURES.add(formatFeatureKey(feature));
}

for (let key of Object.keys(process.env)) {
    if (/^EENGINE_FEATURE_/i.test(key)) {
        let feature = formatFeatureKey(key.substring('EENGINE_FEATURE_'.length));
        if (feature) {
            let value = /^y|1|t/i.test((process.env[key] || '').toString().trim());
            if (value) {
                FEATURES.add(feature);
            } else {
                FEATURES.remove(feature);
            }
        }
    }
}

module.exports = {
    enabled(key) {
        return FEATURES.has(formatFeatureKey(key));
    }
};
