'use strict';

// lib/command-budget.js: a command that waited for its account runs on what is left of its budget

const test = require('node:test');
const assert = require('node:assert').strict;

const { remainingTimeout, MIN_COMMAND_TIMEOUT } = require('../lib/command-budget');

test('remainingTimeout()', () => {
    assert.equal(remainingTimeout(10000, 1000, 1000), 10000, 'nothing spent yet');
    assert.equal(remainingTimeout(10000, 1000, 8000), 3000, 'what is left after the wait');
    assert.equal(remainingTimeout(10000, 1000, 11000 - MIN_COMMAND_TIMEOUT + 1), 0, 'too little left to start');
    assert.equal(remainingTimeout(10000, 1000, 12000), 0, 'spent');
});
