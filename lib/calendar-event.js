'use strict';

// The calendar event EmailEngine reports from an iCalendar attachment (text/calendar or
// application/ics). Shared by the IMAP sync (lib/email-client/imap/mailbox.js) and the API
// clients (lib/email-client/base-client.js), which used to carry two copies of this parse.
//
// A DTSTART or DTEND carrying a TZID is resolved against the VTIMEZONE embedded in the same
// VCALENDAR (ical.js 2.x; 1.x read such a value as floating, in the server's own zone), so the
// ISO timestamps are the instant the invite means wherever EmailEngine happens to run.

const ical = require('ical.js');

const CALENDAR_CONTENT_TYPES = ['text/calendar', 'application/ics'];

// text/calendar before application/ics: when an invite arrives as both, the first attachment
// seen for an event UID is the one reported, and text/calendar is the part the sending client
// marked as the calendar payload
function sortCalendarAttachments(a, b) {
    if (a.contentType !== b.contentType) {
        if (a.contentType === 'text/calendar') {
            return -1;
        }
        if (b.contentType === 'text/calendar') {
            return 1;
        }
    }
    return a.contentType.localeCompare(b.contentType);
}

/**
 * Reads the first VEVENT of an iCalendar document
 *
 * @param {string|Buffer} content - iCalendar text
 * @returns {object|null} The event fields, or null when the document holds no VEVENT with a UID
 * @throws When the content is not parseable iCalendar data
 */
function parseCalendarEvent(content) {
    const comp = new ical.Component(ical.parse(content.toString()));

    const vevent = comp.getFirstSubcomponent('vevent');
    if (!vevent) {
        return null;
    }

    // REQUEST, CANCEL, REPLY and so on
    const methodProp = comp.getFirstProperty('method');

    const event = new ical.Event(vevent);
    if (!event.uid) {
        return null;
    }

    let timezone;
    const vtz = comp.getFirstSubcomponent('vtimezone');
    if (vtz) {
        const tz = new ical.Timezone(vtz);
        timezone = tz && tz.tzid;
    }

    let startDate = event.startDate && event.startDate.toJSDate();
    // Without a DTEND the end is a copy of the start, and with neither the getter throws. A
    // cancellation may carry no DTSTART at all (RFC 5546 3.2.5), so the end is only read when
    // there is something to answer it from
    let endDate = startDate || vevent.hasProperty('dtend') ? event.endDate && event.endDate.toJSDate() : null;

    return {
        eventId: event.uid,
        method: methodProp ? methodProp.getFirstValue() : null,
        summary: event.summary || null,
        description: event.description || null,
        timezone: timezone || null,
        startDate: startDate ? startDate.toISOString() : null,
        endDate: endDate ? endDate.toISOString() : null,
        organizer: event.organizer && typeof event.organizer === 'string' ? event.organizer : null
    };
}

module.exports = { CALENDAR_CONTENT_TYPES, sortCalendarAttachments, parseCalendarEvent };
