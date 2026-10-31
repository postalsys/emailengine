'use strict';

// Sample statistics for the load and chaos reports

function percentile(sorted, p) {
    if (!sorted.length) {
        return null;
    }
    const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
    return sorted[index];
}

/** Count, mean and the usual percentiles of a list of milliseconds, rounded to 0.1ms */
function summarize(samples) {
    const sorted = [...samples].sort((a, b) => a - b);
    const round = value => (value === null ? null : Math.round(value * 10) / 10);
    const mean = sorted.length ? sorted.reduce((sum, value) => sum + value, 0) / sorted.length : null;
    return {
        count: sorted.length,
        mean: round(mean),
        p50: round(percentile(sorted, 50)),
        p90: round(percentile(sorted, 90)),
        p95: round(percentile(sorted, 95)),
        p99: round(percentile(sorted, 99)),
        max: round(sorted.length ? sorted[sorted.length - 1] : null)
    };
}

/** Prometheus text format, reduced to the unlabelled samples of the metric names asked for */
function parsePrometheus(text, names) {
    const values = {};
    for (const line of text.split('\n')) {
        for (const name of names) {
            if (line.startsWith(`${name} `)) {
                values[name] = Number(line.slice(name.length + 1));
            }
        }
    }
    return values;
}

module.exports = { summarize, percentile, parsePrometheus };
