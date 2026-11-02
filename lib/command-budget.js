'use strict';

// The time budget of an account command that waits before it runs.
//
// A command from an API worker carries a timeout, and the worker gives up on the whole command when
// it runs out. The main thread may first wait for the account to settle on an owner (an account
// moving between workers or instances), and then run the command here or on another instance, each
// of which times the command by that same value: the wait and the run together could outlast the
// worker's timer, which answered the client while the command still ran. So what the command gets
// to run on is what is left of the budget (server.js commandAccountOperation()).

// Less than this left is not worth starting a command for: it would be cut off before it answered
const MIN_COMMAND_TIMEOUT = 1000;

/**
 * What is left of a command's budget
 * @param {number} budget - Milliseconds the command was given in all
 * @param {number} startedAt - When the budget started
 * @param {number} [now]
 * @returns {number} Milliseconds, 0 when too little is left to start the command
 */
function remainingTimeout(budget, startedAt, now = Date.now()) {
    const left = budget - (now - startedAt);
    return left >= MIN_COMMAND_TIMEOUT ? left : 0;
}

module.exports = { remainingTimeout, MIN_COMMAND_TIMEOUT };
