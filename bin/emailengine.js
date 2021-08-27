#!/usr/bin/env node
/* eslint global-require: 0 */
'use strict';

if (process.argv[2] === 'encrypt') {
    // encrypt account passwords
    require('../encrypt');
} else if (process.argv[2] === 'scan') {
    // Scan Redis keys
    require('../scan');
} else {
    // run normally
    require('../server');
}
