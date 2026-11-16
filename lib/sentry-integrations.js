'use strict';

// The three event integrations EmailEngine's error reports carry, written for @sentry/core, which
// ships none of them. They used to come from @sentry/node-core, whose 10.x line had no successor:
// Sentry 11 moved its Node.js SDK onto packages that pull the FSL-licensed Sentry CLI and a native
// parser into the tree (see .ncurc.js). Each produces the same event fields as the node-core one it
// replaces, so reports read the same in Sentry:
//
//   ContextLines - pre_context / context_line / post_context around each stack frame
//   Context      - the app, os, device and culture contexts
//   Modules      - name and version of the packages the process has loaded
//
// Nothing here runs a command: the operating system is read from files (node-core ran sw_vers on
// macOS), see "Pure JavaScript only" in CLAUDE.md.

const fs = require('node:fs');
const os = require('node:os');
const pathlib = require('node:path');
const { defineIntegration, snipLine } = require('@sentry/core');

const CONTEXT_LINES = 7;
// Frames past these are minified or generated code, where a source line is noise
const MAX_LINENO = 10000;
const MAX_COLNO = 1000;
// A source file larger than this is not read for context
const MAX_SOURCE_SIZE = 2 * 1024 * 1024;
const SOURCE_FILE = /\.(?:[cm]?[jt]sx?)$/i;
const MAX_CACHED_FILES = 10;

// filename -> lines (index 0 is line 1), or null when the file could not be read
const sourceCache = new Map();

function cacheSource(filename, lines) {
    sourceCache.delete(filename);
    sourceCache.set(filename, lines);
    while (sourceCache.size > MAX_CACHED_FILES) {
        sourceCache.delete(sourceCache.keys().next().value);
    }
}

async function readSourceLines(filename) {
    if (sourceCache.has(filename)) {
        let lines = sourceCache.get(filename);
        cacheSource(filename, lines);
        return lines;
    }
    let lines = null;
    try {
        let stat = await fs.promises.stat(filename);
        if (stat.isFile() && stat.size <= MAX_SOURCE_SIZE) {
            lines = (await fs.promises.readFile(filename, 'utf8')).split(/\r?\n/);
        }
    } catch {
        // unreadable, e.g. a frame from Node's own internals or a file removed since
    }
    cacheSource(filename, lines);
    return lines;
}

function wantsContext(frame) {
    let filename = frame && frame.filename;
    return (
        typeof filename === 'string' &&
        typeof frame.lineno === 'number' &&
        frame.lineno <= MAX_LINENO &&
        !(frame.colno > MAX_COLNO) &&
        !filename.startsWith('node:') &&
        !filename.startsWith('data:') &&
        !/\.min\.[cm]?js$/i.test(filename) &&
        SOURCE_FILE.test(filename)
    );
}

/**
 * Adds the source lines around a frame's line, the way node-core's ContextLines did: up to seven
 * lines before and after, each shortened by snipLine(). A frame whose line is not in the file gets
 * no context at all.
 *
 * @param {Object} frame Sentry stack frame
 * @param {string[]} lines The file's lines
 */
function addContextToFrame(frame, lines) {
    let index = frame.lineno - 1;
    if (index < 0 || index >= lines.length) {
        return;
    }
    let start = Math.max(0, index - CONTEXT_LINES);
    frame.pre_context = lines.slice(start, index).map(line => snipLine(line, 0));
    frame.context_line = snipLine(lines[index], 0);
    frame.post_context = lines.slice(index + 1, index + 1 + CONTEXT_LINES).map(line => snipLine(line, 0));
}

async function addSourceContext(event) {
    let frames = [];
    for (let exception of (event.exception && event.exception.values) || []) {
        for (let frame of (exception.stacktrace && exception.stacktrace.frames) || []) {
            if (frame.context_line === undefined && wantsContext(frame)) {
                frames.push(frame);
            }
        }
    }
    let files = [...new Set(frames.map(frame => frame.filename))];
    let sources = new Map(await Promise.all(files.map(async filename => [filename, await readSourceLines(filename)])));
    for (let frame of frames) {
        let lines = sources.get(frame.filename);
        if (lines) {
            addContextToFrame(frame, lines);
        }
    }
    return event;
}

const contextLinesIntegration = defineIntegration(() => ({
    name: 'ContextLines',
    processEvent: event => addSourceContext(event)
}));

// Darwin kernel major -> macOS major, used only when SystemVersion.plist cannot be read
function macosFromKernel(release) {
    let major = Number(String(release).split('.')[0]);
    return major >= 25 ? String(major + 1) : major >= 20 ? String(major - 9) : `10.${major - 4}`;
}

function plistValue(plist, key) {
    let match = plist.match(new RegExp(`<key>${key}</key>\\s*<string>([^<]*)</string>`));
    return match ? match[1] : undefined;
}

function osReleaseValue(content, key) {
    let match = content.match(new RegExp(`^${key}=(.*)$`, 'm'));
    return match ? match[1].trim().replace(/^(["'])(.*)\1$/, '$2') : undefined;
}

/**
 * The `os` context: name, version, kernel_version and (macOS) build.
 *
 * @param {Object} [env] Injected by the tests
 * @returns {Promise<Object>}
 */
async function getOsContext(env = { platform: process.platform, readFile: fs.promises.readFile, os }) {
    let kernel = env.os.release();
    switch (env.platform) {
        case 'darwin': {
            let context = { kernel_version: kernel, name: 'macOS', version: macosFromKernel(kernel) };
            try {
                let plist = await env.readFile('/System/Library/CoreServices/SystemVersion.plist', 'utf8');
                context.name = plistValue(plist, 'ProductName') || context.name;
                context.version = plistValue(plist, 'ProductVersion') || context.version;
                let build = plistValue(plist, 'ProductBuildVersion');
                if (build) {
                    context.build = build;
                }
            } catch {
                // keep what the kernel version says
            }
            return context;
        }
        case 'linux': {
            let context = { kernel_version: kernel, name: 'Linux' };
            try {
                let content = await env.readFile('/etc/os-release', 'utf8');
                context.name = osReleaseValue(content, 'NAME') || context.name;
                let version = osReleaseValue(content, 'VERSION_ID');
                if (version) {
                    context.version = version;
                }
            } catch {
                // a container without the file
            }
            return context;
        }
        case 'win32':
            return { name: 'Windows', version: env.os.release(), kernel_version: env.os.version() };
        default:
            return { name: env.platform, version: kernel };
    }
}

function getAppContext() {
    let context = {
        app_start_time: new Date(Date.now() - process.uptime() * 1000).toISOString(),
        app_memory: process.memoryUsage().rss
    };
    if (typeof process.availableMemory === 'function') {
        context.free_memory = process.availableMemory();
    }
    return context;
}

function getDeviceContext() {
    let context = {};
    try {
        context.boot_time = new Date(Date.now() - os.uptime() * 1000).toISOString();
    } catch {
        // not available on every platform
    }
    context.arch = os.arch();
    context.memory_size = os.totalmem();
    context.free_memory = os.freemem();
    let cpus = os.cpus();
    if (cpus && cpus.length) {
        context.processor_count = cpus.length;
        context.cpu_description = cpus[0].model;
        context.processor_frequency = cpus[0].speed;
    }
    return context;
}

function getCultureContext() {
    try {
        let { locale, timeZone } = Intl.DateTimeFormat().resolvedOptions();
        return { locale, timezone: timeZone };
    } catch {
        return undefined;
    }
}

const nodeContextIntegration = defineIntegration(() => {
    // what does not change while the process runs is read once
    let osContext = getOsContext();
    let cultureContext = getCultureContext();

    return {
        name: 'Context',
        async processEvent(event) {
            let contexts = event.contexts || {};
            event.contexts = {
                ...contexts,
                app: { ...getAppContext(), ...contexts.app },
                os: { ...(await osContext), ...contexts.os },
                device: { ...getDeviceContext(), ...contexts.device },
                ...(cultureContext ? { culture: { ...cultureContext, ...contexts.culture } } : {})
            };
            return event;
        }
    };
});

// The package a loaded file belongs to: the directory right below its last node_modules segment
// (two levels for a scoped package)
function packageDirOf(filename) {
    let parts = filename.split(/[\\/]/);
    let index = parts.lastIndexOf('node_modules');
    if (index < 0 || index + 1 >= parts.length - 1) {
        return null;
    }
    let depth = parts[index + 1].startsWith('@') ? 2 : 1;
    return parts.slice(0, index + 1 + depth).join(pathlib.sep);
}

/**
 * Name and version of every package something in the process has loaded, read from the
 * package.json files next to the entries of require.cache, plus the application's own
 * dependency list.
 *
 * @param {string[]} [loaded] Loaded file names, injected by the tests
 * @returns {Object} { [name]: version }
 */
function collectModules(loaded = Object.keys(require.cache)) {
    let modules = {};
    try {
        let app = require('../package.json');
        Object.assign(modules, app.dependencies);
    } catch {
        // not expected, the package file ships with every build
    }
    let seen = new Set();
    for (let filename of loaded) {
        let dir = packageDirOf(filename);
        if (!dir || seen.has(dir)) {
            continue;
        }
        seen.add(dir);
        try {
            let info = JSON.parse(fs.readFileSync(pathlib.join(dir, 'package.json'), 'utf8'));
            if (info.name && info.version) {
                modules[info.name] = info.version;
            }
        } catch {
            // a directory without a readable package.json
        }
    }
    return modules;
}

const modulesIntegration = defineIntegration(() => {
    let modules;
    return {
        name: 'Modules',
        processEvent(event) {
            // collected on the first event, when the process has loaded what it is going to load
            modules = modules || collectModules();
            event.modules = { ...event.modules, ...modules };
            return event;
        }
    };
});

module.exports = {
    contextLinesIntegration,
    nodeContextIntegration,
    modulesIntegration,
    // exported for the tests
    addContextToFrame,
    getOsContext,
    collectModules,
    packageDirOf
};
