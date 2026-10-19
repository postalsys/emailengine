'use strict';

// lib/timezones.js builds the timezone select on the admin Service page from the runtime's ICU
// data. The page handlers are driven through the real route table against an isolated Redis
// prefix, because what matters is what an operator sees and what a save stores.

const test = require('node:test');
const assert = require('node:assert').strict;

process.env.EENGINE_REDIS_PREFIX = 'test_timezones';

const { listTimezones, timezoneOptions, IANA_NAMES } = require('../lib/timezones');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { captureRouteConfigs } = require('./helpers/capture-ui-routes');
const { compileView } = require('./helpers/admin-templates');

registerRedisTeardown(redis, async () => {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length > 0) {
        await redis.del(keys);
    }
});

test('listTimezones', async t => {
    const zones = listTimezones();
    const names = zones.map(zone => zone.timezone);

    await t.test('lists every zone the runtime knows, once', () => {
        assert.ok(zones.length >= 400, `${zones.length} zones`);
        assert.equal(new Set(names).size, names.length);
    });

    await t.test('uses the current IANA names, not the CLDR spellings Intl reports', () => {
        for (const [legacy, current] of IANA_NAMES) {
            assert.ok(!names.includes(legacy), `${legacy} is listed`);
            assert.ok(names.includes(current), `${current} is missing`);
        }
    });

    await t.test('maps only ids Intl accepts, onto names Intl also accepts', () => {
        for (const [legacy, current] of IANA_NAMES) {
            for (const timeZone of [legacy, current]) {
                assert.doesNotThrow(() => new Intl.DateTimeFormat('en', { timeZone }), timeZone);
            }
        }
    });

    await t.test('labels each zone with its standard offset, daylight saving time ignored', () => {
        const byName = Object.fromEntries(zones.map(zone => [zone.timezone, zone.label]));
        assert.equal(byName['Europe/Tallinn'], 'Europe/Tallinn (GMT+02:00)');
        assert.equal(byName['Europe/Kyiv'], 'Europe/Kyiv (GMT+02:00)');
        assert.equal(byName['Asia/Kolkata'], 'Asia/Kolkata (GMT+05:30)');
        assert.equal(byName['America/St_Johns'], 'America/St_Johns (GMT-03:30)');
        assert.equal(byName['America/New_York'], 'America/New_York (GMT-05:00)');
        // southern hemisphere: daylight saving time falls in January
        assert.equal(byName['Australia/Sydney'], 'Australia/Sydney (GMT+10:00)');
        assert.equal(byName['Pacific/Chatham'], 'Pacific/Chatham (GMT+12:45)');
        assert.equal(byName['Africa/Abidjan'], 'Africa/Abidjan (GMT+00:00)');
    });

    await t.test('orders by offset, then by name', () => {
        for (let i = 1; i < zones.length; i++) {
            const prev = zones[i - 1];
            const cur = zones[i];
            assert.ok(
                prev.offset < cur.offset || (prev.offset === cur.offset && prev.timezone.localeCompare(cur.timezone) < 0),
                `${prev.timezone} before ${cur.timezone}`
            );
        }
    });
});

test('timezoneOptions', async t => {
    await t.test('selects the stored zone', () => {
        const selected = timezoneOptions('Asia/Kolkata').filter(option => option.selected);
        assert.deepEqual(selected, [{ name: 'Asia/Kolkata (GMT+05:30)', timezone: 'Asia/Kolkata', selected: true }]);
    });

    await t.test('selects nothing when no zone is stored', () => {
        for (const stored of [false, null, undefined, '']) {
            assert.ok(!timezoneOptions(stored).some(option => option.selected));
        }
    });

    await t.test('keeps a stored zone the runtime no longer lists, so saving the page does not change it', () => {
        // merged into America/Edmonton by IANA, offered by the package this module replaced
        const options = timezoneOptions('America/Yellowknife');
        assert.deepEqual(options[0], { name: 'America/Yellowknife (GMT-07:00)', timezone: 'America/Yellowknife', selected: true });
        assert.equal(options.filter(option => option.selected).length, 1);
        assert.equal(options.length, listTimezones().length + 1);
    });

    await t.test('keeps a stored value Intl does not know at all, without an offset', () => {
        assert.deepEqual(timezoneOptions('Mars/Olympus_Mons')[0], { name: 'Mars/Olympus_Mons', timezone: 'Mars/Olympus_Mons', selected: true });
    });
});

test('admin Service page timezone', async t => {
    const routes = captureRouteConfigs().filter(route => route.path === '/admin/config/service');
    const get = routes.find(route => route.method === 'GET');
    const post = routes.find(route => route.method === 'POST');

    const render = async () => {
        let context;
        await get.handler({}, { view: (view, ctx) => (context = ctx) });
        return context;
    };

    const save = async form => {
        const { value, error } = post.options.validate.payload.validate(form, post.options.validate.options);
        assert.ifError(error);
        return await post.handler(
            { payload: value, flash: async () => {}, logger: { error() {}, debug() {}, warn() {}, info() {} } },
            { redirect: path => ({ redirect: path }), view: () => assert.fail('the save failed') }
        );
    };

    const form = timezone => ({ serviceUrl: '', queueKeep: '0', locale: 'en', timezone });

    t.beforeEach(async () => {
        await settings.clear('timezone');
    });

    await t.test('offers the zone list with the stored zone selected', async () => {
        await settings.set('timezone', 'Europe/Kyiv');
        const context = await render();
        assert.equal(context.values.timezone, 'Europe/Kyiv');
        assert.deepEqual(
            context.timezones.filter(option => option.selected),
            [{ name: 'Europe/Kyiv (GMT+02:00)', timezone: 'Europe/Kyiv', selected: true }]
        );
    });

    await t.test('selects nothing in the list when no zone is stored', async () => {
        const context = await render();
        assert.equal(context.values.timezone, false);
        assert.ok(!context.timezones.some(option => option.selected));
    });

    await t.test('stores the chosen zone', async () => {
        assert.deepEqual(await save(form('Asia/Kolkata')), { redirect: '/admin/config/service' });
        assert.equal(await settings.get('timezone'), 'Asia/Kolkata');
    });

    await t.test('a blank choice while no zone is stored writes nothing', async () => {
        // the browser report on the next admin page load fills it in (/admin/config/browser)
        await save(form(''));
        assert.equal(await redis.hexists(`${REDIS_PREFIX}settings`, 'timezone'), 0);
    });

    await t.test('a blank choice leaves a stored zone alone', async () => {
        await settings.set('timezone', 'Europe/Tallinn');
        await save(form(''));
        assert.equal(await settings.get('timezone'), 'Europe/Tallinn');
    });

    await t.test('the select starts on "Not set" only while no zone is stored', async () => {
        const template = compileView('config/service.hbs');
        const selectHtml = html => html.slice(html.indexOf('id="settingsServiceTimezone"'), html.indexOf('</select>'));

        const unset = selectHtml(template(await render()));
        assert.match(unset, /<option value="" selected>Not set<\/option>/);
        assert.equal((unset.match(/ selected>/g) || []).length, 1);

        await settings.set('timezone', 'Europe/Kyiv');
        const stored = selectHtml(template(await render()));
        assert.ok(!stored.includes('Not set'));
        assert.match(stored, /<option value="Europe\/Kyiv" selected>Europe\/Kyiv \(GMT\+02:00\)<\/option>/);
    });
});
