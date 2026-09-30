'use strict';

// Boolean query flags are declared `.truthy('Y', 'true', '1').falsy('N', 'false', ...)`. The falsy
// list used to carry the NUMBER 0, which a query string never delivers, so `?force=1` worked while
// `?force=0` was refused with a 400. Checked against every route's real query schema, so a flag
// added later with the old spelling fails here.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { captureApiRoutes } = require('./helpers/capture-api-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

test('boolean query flags accept the string forms of both values', async t => {
    const { routes } = await captureApiRoutes();

    await t.test('?force=0 on DELETE message parses to false', () => {
        const route = routes.find(r => r.route === 'DELETE /v1/account/{account}/message/{message}');
        assert.ok(route);
        const { value, error } = route.settings.validate.query.validate({ force: '0' });
        assert.ifError(error);
        assert.equal(value.force, false);
        assert.equal(route.settings.validate.query.validate({ force: '1' }).value.force, true);
    });

    await t.test('every flag that takes "1" also takes "0"', () => {
        const refused = [];
        let checked = 0;
        for (const route of routes) {
            const query = route.settings.validate && route.settings.validate.query;
            if (!query || typeof query.describe !== 'function') {
                continue;
            }
            const keys = query.describe().keys || {};
            for (const [key, description] of Object.entries(keys)) {
                const truthy = description.truthy || [];
                if (description.type !== 'boolean' || !truthy.includes('1')) {
                    continue;
                }
                checked++;
                // The whole query schema, so sibling references resolve; only this key's own
                // errors count, since another key may be required
                const { value, error } = query.validate({ [key]: '0' }, { convert: true, abortEarly: false });
                // `any.unknown` is a flag that only exists beside another one, which is not what
                // this checks
                const ownError = error && error.details.some(detail => detail.path[0] === key && detail.type !== 'any.unknown');
                if (error && !ownError) {
                    continue;
                }
                if (ownError || !value || value[key] !== false) {
                    refused.push(`${route.route} ?${key}=0`);
                }
            }
        }
        assert.ok(checked > 10, `only ${checked} flags found, the sweep is not reading the schemas`);
        assert.deepEqual(refused, []);
    });
});
