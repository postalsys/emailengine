'use strict';

// lib/utils/tracking-settings.js: which tracking a sent message gets. The rule used to be written
// inline in BaseClient.queueMessage() with every typeof check twice; the property below holds the
// module to that original rule, copied here as the oracle, over every mix of message flags and
// stored settings, including values that are not booleans.

const test = require('node:test');
const assert = require('node:assert').strict;

const { needsTrackingSettings, resolveTracking } = require('../lib/utils/tracking-settings');
const { forAll, gen } = require('./helpers/property');

// The rule as base-client.js wrote it before the module existed, with sequential setting reads
function originalRule(message, stored) {
    let { trackingEnabled, trackClicks, trackOpens } = message;
    if (typeof trackingEnabled !== 'boolean') {
        trackingEnabled = stored.trackSentMessages || false;
    }
    if (typeof trackClicks !== 'boolean') {
        trackClicks = stored.trackClicks;
        if (typeof trackClicks !== 'boolean') {
            trackClicks = trackingEnabled;
        }
    }
    if (typeof trackOpens !== 'boolean') {
        trackOpens = stored.trackOpens;
        if (typeof trackOpens !== 'boolean') {
            trackOpens = trackingEnabled;
        }
    }
    return { trackingEnabled, trackClicks, trackOpens };
}

const flag = gen.oneOf([true, false, undefined, null, 'true', 0, 1]);

test('resolveTracking() matches the original inline rule for every input', () => {
    forAll(
        gen.record({
            message: gen.record({ trackingEnabled: flag, trackClicks: flag, trackOpens: flag }),
            stored: gen.record({ trackSentMessages: flag, trackClicks: flag, trackOpens: flag })
        }),
        ({ message, stored }) => {
            assert.deepStrictEqual(resolveTracking(message, stored), originalRule(message, stored));
        }
    );
});

test('the settings are needed exactly when the message leaves a flag open', () => {
    forAll(gen.record({ trackingEnabled: flag, trackClicks: flag, trackOpens: flag }), message => {
        const open = [message.trackingEnabled, message.trackClicks, message.trackOpens].some(value => typeof value !== 'boolean');
        assert.strictEqual(needsTrackingSettings(message), open);
        if (!open) {
            // nothing read: the message's own flags stand without any stored values
            assert.deepStrictEqual(resolveTracking(message), message);
        }
    });
});
