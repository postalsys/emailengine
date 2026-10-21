'use strict';

// lib/calendar-event.js is the one parse behind the `calendarEvents` payload of both the IMAP
// sync and the API clients. The invite below carries its own VTIMEZONE with a DTSTART in that
// zone, which is the shape every calendar client sends: the timestamps must come out as the
// instant the invite means, not as that wall-clock time read in the server's zone.

// Pinned before anything reads a Date, to a zone far from the invite's: a parse that fell back
// to floating time would be off by many hours here and still pass on a UTC machine
process.env.TZ = 'Pacific/Kiritimati';

const test = require('node:test');
const assert = require('node:assert').strict;

const { parseCalendarEvent, sortCalendarAttachments, CALENDAR_CONTENT_TYPES } = require('../lib/calendar-event');

const CRLF = '\r\n';

const TALLINN_VTIMEZONE = [
    'BEGIN:VTIMEZONE',
    'TZID:Europe/Tallinn',
    'BEGIN:STANDARD',
    'DTSTART:19701025T040000',
    'RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU',
    'TZOFFSETFROM:+0300',
    'TZOFFSETTO:+0200',
    'TZNAME:EET',
    'END:STANDARD',
    'BEGIN:DAYLIGHT',
    'DTSTART:19700329T030000',
    'RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU',
    'TZOFFSETFROM:+0200',
    'TZOFFSETTO:+0300',
    'TZNAME:EEST',
    'END:DAYLIGHT',
    'END:VTIMEZONE'
];

function calendar(lines, { method = 'REQUEST', timezone = TALLINN_VTIMEZONE } = {}) {
    return ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//EmailEngine tests//EN', method ? `METHOD:${method}` : null, ...timezone, ...lines, 'END:VCALENDAR']
        .filter(line => line !== null)
        .join(CRLF);
}

const INVITE = calendar([
    'BEGIN:VEVENT',
    'UID:invite-1@example.com',
    'DTSTAMP:20260601T120000Z',
    'DTSTART;TZID=Europe/Tallinn:20260615T100000',
    'DTEND;TZID=Europe/Tallinn:20260615T113000',
    'SUMMARY:Planning meeting',
    'DESCRIPTION:Line one\\nLine two',
    'ORGANIZER;CN=Organizer:mailto:organizer@example.com',
    'END:VEVENT'
]);

test('parseCalendarEvent reads the fields the calendarEvents payload carries', () => {
    assert.deepEqual(parseCalendarEvent(INVITE), {
        eventId: 'invite-1@example.com',
        method: 'REQUEST',
        summary: 'Planning meeting',
        description: 'Line one\nLine two',
        timezone: 'Europe/Tallinn',
        // 10:00 EEST (UTC+3) in June, whatever zone this process runs in
        startDate: '2026-06-15T07:00:00.000Z',
        endDate: '2026-06-15T08:30:00.000Z',
        organizer: 'mailto:organizer@example.com'
    });
});

test('parseCalendarEvent takes a Buffer, as the attachment content arrives', () => {
    assert.equal(parseCalendarEvent(Buffer.from(INVITE)).startDate, '2026-06-15T07:00:00.000Z');
});

test('a UTC DTSTART and an event with no optional fields: the end is a copy of the start', () => {
    const event = parseCalendarEvent(
        calendar(['BEGIN:VEVENT', 'UID:bare-1@example.com', 'DTSTAMP:20260601T120000Z', 'DTSTART:20260615T070000Z', 'END:VEVENT'], {
            method: null,
            timezone: []
        })
    );

    assert.deepEqual(event, {
        eventId: 'bare-1@example.com',
        method: null,
        summary: null,
        description: null,
        timezone: null,
        startDate: '2026-06-15T07:00:00.000Z',
        endDate: '2026-06-15T07:00:00.000Z',
        organizer: null
    });
});

test('a cancellation reports its METHOD, with or without the DTSTART a CANCEL may omit', () => {
    const dated = parseCalendarEvent(
        calendar(['BEGIN:VEVENT', 'UID:invite-1@example.com', 'DTSTAMP:20260601T120000Z', 'DTSTART;TZID=Europe/Tallinn:20260615T100000', 'END:VEVENT'], {
            method: 'CANCEL'
        })
    );
    assert.equal(dated.method, 'CANCEL');
    assert.equal(dated.eventId, 'invite-1@example.com');
    assert.equal(dated.startDate, '2026-06-15T07:00:00.000Z');

    // ical.js derives a missing end from the start, and throws when there is no start either;
    // such a cancellation used to be logged as unparseable instead of reported
    const undated = parseCalendarEvent(calendar(['BEGIN:VEVENT', 'UID:invite-1@example.com', 'DTSTAMP:20260601T120000Z', 'END:VEVENT'], { method: 'CANCEL' }));
    assert.equal(undated.method, 'CANCEL');
    assert.equal(undated.startDate, null);
    assert.equal(undated.endDate, null);

    const endOnly = parseCalendarEvent(
        calendar(['BEGIN:VEVENT', 'UID:invite-1@example.com', 'DTSTAMP:20260601T120000Z', 'DTEND:20260615T080000Z', 'END:VEVENT'], { method: 'CANCEL' })
    );
    assert.equal(endOnly.startDate, null);
    assert.equal(endOnly.endDate, '2026-06-15T08:00:00.000Z');
});

test('a document without a VEVENT, or a VEVENT without a UID, is no event', () => {
    assert.equal(parseCalendarEvent(calendar([])), null);
    assert.equal(parseCalendarEvent(calendar(['BEGIN:VEVENT', 'DTSTAMP:20260601T120000Z', 'SUMMARY:No id', 'END:VEVENT'])), null);
});

test('data that is not iCalendar throws, for the caller to log against the attachment', () => {
    assert.throws(() => parseCalendarEvent('this is not a calendar'));
});

test('sortCalendarAttachments puts text/calendar first and is otherwise stable by type', () => {
    const attachments = [
        { id: 'a', contentType: 'application/ics' },
        { id: 'b', contentType: 'text/calendar' },
        { id: 'c', contentType: 'application/ics' },
        { id: 'd', contentType: 'text/calendar' }
    ];

    assert.deepEqual(
        [...attachments].sort(sortCalendarAttachments).map(a => a.id),
        ['b', 'd', 'a', 'c']
    );
    assert.deepEqual(CALENDAR_CONTENT_TYPES, ['text/calendar', 'application/ics']);
});

test('collectCalendarEvents()', async t => {
    const { collectCalendarEvents } = require('../lib/calendar-event');
    const { createMockLogger } = require('./helpers/mock-logger');
    const b64 = text => Buffer.from(text).toString('base64');

    await t.test('one event per UID, text/calendar first, the file name taken from either part', async () => {
        const loaded = [];
        const attachments = [
            { id: 'ics', contentType: 'application/ics', filename: 'meeting.ics', content: b64(INVITE) },
            { id: 'cal', contentType: 'text/calendar', method: 'REQUEST' },
            { id: 'pdf', contentType: 'application/pdf' }
        ];
        const events = await collectCalendarEvents(
            attachments,
            async attachment => {
                loaded.push(attachment.id);
                attachment.content = b64(INVITE);
            },
            createMockLogger()
        );
        assert.deepStrictEqual(loaded, ['cal'], 'only a calendar part without content is loaded');
        assert.strictEqual(events.length, 1);
        assert.strictEqual(events[0].attachment, 'cal', 'the text/calendar part is the one listed');
        assert.strictEqual(events[0].filename, 'meeting.ics', 'its file name comes from the other part');
        assert.strictEqual(events[0].method, 'REQUEST');
    });

    await t.test('a default file name by method, and nothing for a message without events', async () => {
        const events = await collectCalendarEvents([{ id: 'cal', contentType: 'text/calendar', content: b64(INVITE) }], async () => {}, createMockLogger());
        assert.strictEqual(events[0].filename, 'invite.ics');
        assert.strictEqual(await collectCalendarEvents([{ id: 'pdf', contentType: 'application/pdf' }], async () => {}, createMockLogger()), undefined);
        assert.strictEqual(await collectCalendarEvents(undefined, async () => {}, createMockLogger()), undefined);
    });

    await t.test('a part that does not parse is logged and skipped', async () => {
        const logger = createMockLogger();
        const events = await collectCalendarEvents(
            [{ id: 'bad', contentType: 'text/calendar', content: b64('BEGIN:VCALENDAR\r\nBROKEN') }],
            async () => {},
            logger
        );
        assert.strictEqual(events, undefined);
    });
});

test('loadNotifyAttachments()', async () => {
    const { loadNotifyAttachments } = require('../lib/notify-attachments');
    const loaded = [];
    await loadNotifyAttachments(
        [
            { id: 'small', encodedSize: 100 },
            { id: 'big', encodedSize: 10 * 1024 * 1024 },
            { id: 'have', encodedSize: 100, content: 'x' }
        ],
        1024,
        async attachment => loaded.push(attachment.id)
    );
    assert.deepStrictEqual(loaded, ['small']);
});

test('loadNotifyAttachments() runs up to `concurrency` downloads at once', async () => {
    const { loadNotifyAttachments } = require('../lib/notify-attachments');
    let running = 0;
    let peak = 0;
    const attachments = Array.from({ length: 8 }, (v, i) => ({ id: `a${i}`, encodedSize: 10 }));
    await loadNotifyAttachments(
        attachments,
        1024,
        async attachment => {
            running++;
            peak = Math.max(peak, running);
            await new Promise(resolve => setTimeout(resolve, 5));
            attachment.content = 'x';
            running--;
        },
        3
    );
    assert.strictEqual(peak, 3);
    assert.ok(attachments.every(attachment => attachment.content === 'x'));
});
