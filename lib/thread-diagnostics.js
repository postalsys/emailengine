'use strict';

// What the main thread reports about its worker threads beyond their counts: the fields the
// heartbeat log lines carry and the per-thread event loop delay gauges. Kept free of server.js
// state so both can be tested without starting the process.

/**
 * Fields for a heartbeat log line (unhealthy, restarting, recovered).
 * @param {Object} args
 * @param {number} args.now - Current time in milliseconds
 * @param {number} [args.lastHeartbeat] - When the thread last reported in
 * @param {number} [args.accounts] - Accounts assigned to the thread, for an account worker
 * @param {Object} [args.threadInfo] - The thread's last resource reading. A thread that has gone quiet
 *   cannot answer, so this is the one taken before that, at most one collection interval earlier.
 * @returns {Object} Fields to spread into the log entry
 */
function heartbeatDiagnostics({ now, lastHeartbeat, accounts, threadInfo }) {
    let details = {};
    if (typeof lastHeartbeat === 'number') {
        details.timeSinceHeartbeat = Math.round((now - lastHeartbeat) / 1000) + 's';
    }
    if (typeof accounts === 'number') {
        details.accounts = accounts;
    }
    if (threadInfo?.eventLoopDelay) {
        details.lastEventLoopDelay = Math.round(threadInfo.eventLoopDelay.max) + 'ms';
    }
    return details;
}

/**
 * The per-thread event loop delay gauge values, in seconds, for every thread that has a reading.
 * @param {Array<Object>} threadsInfo - Thread readings as the metrics collector returns them
 * @returns {Array<{labels: Object, max: number, p99: number}>}
 */
function eventLoopDelaySeries(threadsInfo) {
    return (threadsInfo || [])
        .filter(threadInfo => threadInfo.eventLoopDelay)
        .map(threadInfo => ({
            labels: { type: threadInfo.type, thread: String(threadInfo.threadId) },
            max: threadInfo.eventLoopDelay.max / 1000,
            p99: threadInfo.eventLoopDelay.p99 / 1000
        }));
}

/**
 * The per-thread heap gauge values, in bytes, for every thread that answered its resource reading.
 * Heap is the one memory figure that belongs to a thread: rss and external are the process's, and
 * every thread reports the same value for them.
 * @param {Array<Object>} threadsInfo - Thread readings as the metrics collector returns them
 * @returns {Array<{labels: Object, used: number, total: number}>}
 */
function threadHeapSeries(threadsInfo) {
    return (threadsInfo || [])
        .filter(threadInfo => Number.isFinite(threadInfo.heapUsed) && Number.isFinite(threadInfo.heapTotal))
        .map(threadInfo => ({
            labels: { type: threadInfo.type, thread: String(threadInfo.threadId) },
            used: threadInfo.heapUsed,
            total: threadInfo.heapTotal
        }));
}

module.exports = { heartbeatDiagnostics, eventLoopDelaySeries, threadHeapSeries };
