'use strict';

// lib/command-budget.js: a command that waited for its account runs on what is left of its budget

const test = require('node:test');
const assert = require('node:assert').strict;

const { remainingTimeout, commandBudget, connectionWaitTimeout, MIN_COMMAND_TIMEOUT } = require('../lib/command-budget');

test('remainingTimeout()', () => {
    assert.equal(remainingTimeout(10000, 1000, 1000), 10000, 'nothing spent yet');
    assert.equal(remainingTimeout(10000, 1000, 8000), 3000, 'what is left after the wait');
    assert.equal(remainingTimeout(10000, 1000, 11000 - MIN_COMMAND_TIMEOUT + 1), 0, 'too little left to start');
    assert.equal(remainingTimeout(10000, 1000, 12000), 0, 'spent');
});

test("commandBudget() is the command's own timeout, else the default", () => {
    assert.equal(commandBudget(1000, 10000), 1000, 'a budget the main thread cut down is not raised back');
    assert.equal(commandBudget(undefined, 10000), 10000);
    assert.equal(commandBudget(0, 8000), 8000);
});

test('connectionWaitTimeout() holds a command for at most half of its budget', () => {
    // Before, a 1 s command waited up to 5 s and started long after its caller had answered Timeout
    assert.equal(connectionWaitTimeout(1000, 10000), 500);
    assert.equal(connectionWaitTimeout(30000, 10000), 10000, 'capped');
});
