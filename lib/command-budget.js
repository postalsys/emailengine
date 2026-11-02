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

/**
 * A command's whole budget: its own timeout when it carries one, otherwise the default
 * @param {number} [timeout] - The command's timeout
 * @param {number} fallback - The default command timeout
 * @returns {number} Milliseconds
 */
function commandBudget(timeout, fallback) {
    return typeof timeout === 'number' && timeout > 0 ? timeout : fallback;
}

/**
 * How long an IMAP worker may hold a command for a connection that is still starting: half of the
 * command's budget, so the command still has the other half to run and answer in. The budget is the
 * command's own timeout when it carries one, which the main thread has already cut down to what is
 * left (see above), so it must never be raised back to the default here
 * @param {number} budget - The command's budget, see commandBudget()
 * @param {number} cap - The longest wait for any command
 * @returns {number} Milliseconds
 */
function connectionWaitTimeout(budget, cap) {
    return Math.min(cap, budget / 2);
}

module.exports = { remainingTimeout, commandBudget, connectionWaitTimeout, MIN_COMMAND_TIMEOUT };
