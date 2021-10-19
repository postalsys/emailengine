#!/usr/bin/env node
/* eslint global-require: 0 */
'use strict';

const packageData = require('../package.json');
const fs = require('fs');
const pathlib = require('path');

if (process.argv[2] === 'encrypt') {
    // encrypt account passwords
    require('../encrypt');
} else if (process.argv[2] === 'scan') {
    // Scan Redis keys
    require('../scan');
} else if (['version', '-v', '--version'].includes(process.argv[2])) {
    // Show version
    console.log(`EmailEngine v${packageData.version} (${packageData.license})`);
} else if (['license', '--license'].includes(process.argv[2])) {
    // Display license information
    fs.readFile(pathlib.join(__dirname, '..', 'LICENSE.txt'), (err, license) => {
        if (err) {
            console.error('Failed to load license information');
            console.error(err);
            return process.exit(1);
        }

        console.error('EmailEngine License');
        console.error('===================');
        console.log(`EmailEngine v${packageData.version}`);
        console.error(`(c) 2020-2021 Postal Systems`);
        console.error(`${packageData.license}, full text follows`);
        console.error('');

        console.error(license.toString().trim());

        console.error('');

        fs.readFile(pathlib.join(__dirname, '..', 'licenses.txt'), (err, data) => {
            if (err) {
                console.error('Failed to load license information');
                console.error(err);
                return process.exit(1);
            }

            console.error('Included Modules');
            console.error('================');

            console.error(data.toString().trim());
            process.exit();
        });
    });
} else {
    // run normally
    require('../server');
}