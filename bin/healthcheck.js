#!/usr/bin/env node
'use strict';

// The Docker image's HEALTHCHECK: exits 0 when the API answers /health/live, 1 otherwise. See
// lib/health-probe.js.

// Resolve `.env` and `config/` against the application root, in the same order as server.js
process.chdir(require('path').join(__dirname, '..'));
require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const { probeTarget, probe } = require('../lib/health-probe');

const target = probeTarget(config.api || {});

probe(target).then(result => {
    const url = `${target.protocol}://${target.host}:${target.port}`;
    process.stdout.write(result.ok ? `${url} is live\n` : `${url} is not live: ${result.error || `HTTP ${result.statusCode}`}\n`);
    process.exit(result.ok ? 0 : 1);
});
