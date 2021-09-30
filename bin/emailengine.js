#!/usr/bin/env node
/* eslint global-require: 0 */
'use strict';

const packageData = require('../package.json');

if (process.argv[2] === 'encrypt') {
    // encrypt account passwords
    require('../encrypt');
} else if (process.argv[2] === 'scan') {
    // Scan Redis keys
    require('../scan');
} else if (['version', '-v', '--version'].includes(process.argv[2])) {
    // Scan Redis keys
    console.log(`EmailEngine v${packageData.version} (${packageData.license})`);
} else {
    // run normally
    require('../server');
}
