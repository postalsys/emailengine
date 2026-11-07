'use strict';

// Polls until check() resolves truthy or the deadline passes, for state that production code
// changes without the test being able to await it. A fixed sleep either wastes time or, on a loaded
// runner, is not long enough.
async function waitUntil(check, timeoutMs = 2000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        if (await check()) {
            return true;
        }
        if (Date.now() > deadline) {
            return false;
        }
        await new Promise(resolve => setTimeout(resolve, 20));
    }
}

module.exports = waitUntil;
