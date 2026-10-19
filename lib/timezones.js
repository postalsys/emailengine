'use strict';

// The timezone choices on the admin Service page, built from the runtime's own ICU data instead of
// a static package. Node (and the pkg binaries, which carry full ICU) list zones under their CLDR
// ids, and CLDR keeps the old spelling for zones IANA has since renamed: Intl answers
// "Europe/Kiev" and "Asia/Calcutta", never "Europe/Kyiv" or "Asia/Kolkata". Those are shown and
// stored under their IANA names, which is also what the replaced timezones-list package offered, so
// a value saved from the old list stays selected. Intl accepts both spellings as a timeZone.

// CLDR id -> current IANA name, for every id Intl.supportedValuesOf('timeZone') returns in its
// legacy form (checked on Node 20, 24 and 26, all ICU 78)
const IANA_NAMES = new Map([
    ['Africa/Asmera', 'Africa/Asmara'],
    ['America/Buenos_Aires', 'America/Argentina/Buenos_Aires'],
    ['America/Catamarca', 'America/Argentina/Catamarca'],
    ['America/Coral_Harbour', 'America/Atikokan'],
    ['America/Cordoba', 'America/Argentina/Cordoba'],
    ['America/Indianapolis', 'America/Indiana/Indianapolis'],
    ['America/Jujuy', 'America/Argentina/Jujuy'],
    ['America/Louisville', 'America/Kentucky/Louisville'],
    ['America/Mendoza', 'America/Argentina/Mendoza'],
    ['Asia/Calcutta', 'Asia/Kolkata'],
    ['Asia/Katmandu', 'Asia/Kathmandu'],
    ['Asia/Rangoon', 'Asia/Yangon'],
    ['Asia/Saigon', 'Asia/Ho_Chi_Minh'],
    ['Atlantic/Faeroe', 'Atlantic/Faroe'],
    ['Europe/Kiev', 'Europe/Kyiv'],
    ['Pacific/Ponape', 'Pacific/Pohnpei'],
    ['Pacific/Truk', 'Pacific/Chuuk']
]);

// Offsets are read on these dates so the label shows the standard offset all year round instead
// of moving with daylight saving time: the smaller of a January and a July offset is the standard
// one in both hemispheres
const SAMPLE_DATES = [new Date(Date.UTC(2026, 0, 1)), new Date(Date.UTC(2026, 6, 1))];

/**
 * @param {string} timeZone
 * @param {Date} date
 * @returns {number|null} UTC offset in minutes, or null for an unknown zone
 */
function getOffsetMinutes(timeZone, date) {
    let name;
    try {
        name = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'longOffset' }).formatToParts(date).find(part => part.type === 'timeZoneName').value;
    } catch {
        return null;
    }
    // "GMT" alone is UTC, otherwise "GMT+05:30" / "GMT-03:00"
    const match = name.match(/^GMT(?:([+-])(\d{2}):(\d{2}))?$/);
    if (!match) {
        return null;
    }
    return match[1] ? (match[1] === '-' ? -1 : 1) * (Number(match[2]) * 60 + Number(match[3])) : 0;
}

// The standard offset of a zone, null when the runtime does not know it
function getStandardOffset(timeZone) {
    const offsets = SAMPLE_DATES.map(date => getOffsetMinutes(timeZone, date)).filter(offset => offset !== null);
    return offsets.length ? Math.min(...offsets) : null;
}

function formatOffset(minutes) {
    const sign = minutes < 0 ? '-' : '+';
    const abs = Math.abs(minutes);
    return `GMT${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`;
}

let cachedZones = null;

/**
 * Every zone the runtime knows under its IANA name, ordered by standard offset and then by name.
 *
 * @returns {{ timezone: string, offset: number, label: string }[]}
 */
function listTimezones() {
    if (!cachedZones) {
        const zones = new Map();
        for (const id of Intl.supportedValuesOf('timeZone')) {
            const timezone = IANA_NAMES.get(id) || id;
            const offset = getStandardOffset(id);
            if (offset === null || zones.has(timezone)) {
                continue;
            }
            zones.set(timezone, { timezone, offset, label: `${timezone} (${formatOffset(offset)})` });
        }
        cachedZones = [...zones.values()].sort((a, b) => a.offset - b.offset || a.timezone.localeCompare(b.timezone));
    }
    return cachedZones;
}

/**
 * Options for the timezone select. A stored value the runtime does not list (a zone IANA has
 * since merged into another, like America/Yellowknife) is kept as an option of its own, so opening
 * and saving the page never changes it.
 *
 * @param {string|false|null|undefined} selected The stored timezone
 * @returns {{ name: string, timezone: string, selected: boolean }[]}
 */
function timezoneOptions(selected) {
    const options = listTimezones().map(zone => ({ name: zone.label, timezone: zone.timezone, selected: zone.timezone === selected }));
    if (selected && !options.some(option => option.selected)) {
        const offset = getStandardOffset(selected);
        options.unshift({ name: offset === null ? selected : `${selected} (${formatOffset(offset)})`, timezone: selected, selected: true });
    }
    return options;
}

module.exports = { listTimezones, timezoneOptions, IANA_NAMES };
