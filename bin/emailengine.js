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

        fs.readFile(pathlib.join(__dirname, '..', 'LICENSE_EMAILENGINE.txt'), (err, licenseComm) => {
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

            console.error('-'.repeat(78));
            console.error(license.toString().trim());

            console.error('');
            console.error('-'.repeat(78));
            console.error('');

            console.error(licenseComm.toString().trim());
            console.error('-'.repeat(78));
            console.error('');

            process.exit();
        });
    });
} else {
    // run normally
    require('../server');
}
