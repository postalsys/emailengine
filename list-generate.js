'use strict';

// Regenerates static/licenses.html - the open source license listing served
// at /licenses.html. Collects every production dependency (npm ls --omit=dev),
// the build-time packages whose output is embedded in the compiled UI assets,
// and the hand-vendored assets, together with each package's license text.
//
// Every npm package must satisfy ALLOWED_LICENSES (spdx-satisfies) or the
// script exits non-zero - this gate is what keeps restrictively licensed
// packages (the apexcharts trap) out of the tree. Run via `npm run licenses`;
// the output is committed so builds stay deterministic.

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const he = require('he');
const satisfies = require('spdx-satisfies');
const packageData = require('./package.json');

const ALLOWED_LICENSES = [
    'ISC',
    'MIT',
    'Apache-1.0+',
    'CC-BY-3.0',
    'BSD-2-Clause',
    'BSD-3-Clause',
    '0BSD',
    'CC0-1.0',
    'MIT-0',
    'MPL-2.0',
    'Python-2.0',
    'BlueOak-1.0.0'
];

// Build-time packages whose output ships inside the compiled UI assets
// (static/css/flyonui.css, static/js/flyonui.js)
const ASSET_PACKAGES = ['tailwindcss', 'flyonui', '@iconify/tailwind4', '@iconify-json/tabler'];

// Packages whose package.json declares no (or an unparseable) license even
// though their shipped LICENSE file is clear. Keep each entry justified; fix
// upstream where we control the package.
const LICENSE_OVERRIDES = {
    // our own package; the LICENSE file is MIT but package.json lacks the
    // license field (fix upstream in postalsys/gettext, then drop this)
    '@postalsys/gettext': 'MIT',
    // declares the free-text "MIT (http://mootools.net/license.txt)"
    // instead of an SPDX id
    slick: 'MIT'
};

// Hand-vendored assets that are not npm dependencies. gateExempt entries skip
// the SPDX allow-list (fonts are static assets, not linked code).
const EXTRA_ASSETS = [
    {
        name: 'PT Sans',
        version: '',
        license: 'OFL-1.1',
        homepage: 'https://fonts.google.com/specimen/PT+Sans',
        licenseFile: path.join(__dirname, 'static', 'fonts', 'pt-sans', 'OFL.txt'),
        gateExempt: true
    },
    {
        name: 'highlight.js',
        version: '11.5.1',
        license: 'BSD-3-Clause',
        homepage: 'https://highlightjs.org/',
        licenseFile: null,
        gateExempt: false
    }
];

function prodDependencyPaths() {
    let out;
    try {
        out = execFileSync('npm', ['ls', '--omit=dev', '--all', '--parseable'], { cwd: __dirname, encoding: 'utf8' });
    } catch (err) {
        // npm ls exits non-zero on peer-dep warnings but still prints the tree
        out = err.stdout || '';
    }
    return out.split('\n').filter(p => p.includes(`${path.sep}node_modules${path.sep}`));
}

function findLicenseText(dir) {
    let entries;
    try {
        entries = fs.readdirSync(dir);
    } catch (err) {
        return null;
    }
    let candidate = entries.find(f => /^(license|licence|copying)(\.|$)/i.test(f));
    if (!candidate) {
        return null;
    }
    try {
        let text = fs.readFileSync(path.join(dir, candidate), 'utf8').trim();
        return text || null;
    } catch (err) {
        return null;
    }
}

function homepageOf(pkg) {
    let url = pkg.homepage;
    if (!url) {
        let repo = typeof pkg.repository === 'string' ? pkg.repository : pkg.repository && pkg.repository.url;
        if (repo) {
            url = repo
                .replace(/^git\+/, '')
                .replace(/^git:\/\//, 'https://')
                .replace(/^ssh:\/\/git@/, 'https://')
                .replace(/\.git$/, '');
        }
    }
    // the value is third-party package metadata rendered into an href -
    // allow-list the scheme so a hostile field cannot smuggle javascript:
    return url && /^https?:\/\//i.test(url) ? url : null;
}

// returns an error string, or null when the license passes the gate
function verifyLicense(entry) {
    if (entry.gateExempt) {
        return null;
    }
    if (!entry.license) {
        return `No license declared for ${entry.name}`;
    }
    try {
        if (!satisfies(entry.license, ALLOWED_LICENSES)) {
            return `Failed to verify license for ${entry.name}. Found: "${entry.license}"`;
        }
    } catch (err) {
        return `Failed to parse license "${entry.license}" for ${entry.name}: ${err.message}`;
    }
    return null;
}

const packages = new Map(); // name@version -> entry

function collect(dirs, section) {
    for (let dir of dirs) {
        let pkgFile = path.join(dir, 'package.json');
        if (!fs.existsSync(pkgFile)) {
            continue;
        }
        let pkg;
        try {
            pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
        } catch (err) {
            continue;
        }
        if (pkg.private || !pkg.name || pkg.name === packageData.name) {
            continue;
        }
        let key = `${pkg.name}@${pkg.version}`;
        let entry = packages.get(key);
        if (!entry) {
            entry = {
                name: pkg.name,
                version: pkg.version || '',
                license: LICENSE_OVERRIDES[pkg.name] || (typeof pkg.license === 'string' ? pkg.license : (pkg.license && pkg.license.type) || ''),
                homepage: homepageOf(pkg),
                sections: [],
                licenseText: findLicenseText(dir)
            };
            packages.set(key, entry);
        }
        if (!entry.sections.includes(section)) {
            entry.sections.push(section);
        }
    }
}

collect(prodDependencyPaths(), 'runtime');
collect(
    ASSET_PACKAGES.map(name => path.join(__dirname, 'node_modules', name)),
    'assets'
);

// A build-embed package belongs in "assets" even when it also entered the
// tree as a regular dependency
for (let entry of packages.values()) {
    if (ASSET_PACKAGES.includes(entry.name)) {
        entry.sections = ['assets'];
    }
}

for (let extra of EXTRA_ASSETS) {
    packages.set(`${extra.name}@${extra.version}`, {
        name: extra.name,
        version: extra.version,
        license: extra.license,
        homepage: extra.homepage,
        sections: ['assets'],
        licenseText: extra.licenseFile && fs.existsSync(extra.licenseFile) ? fs.readFileSync(extra.licenseFile, 'utf8').trim() : null,
        gateExempt: extra.gateExempt
    });
}

const list = [...packages.values()].sort((a, b) => a.name.localeCompare(b.name));
const violations = list.map(verifyLicense).filter(Boolean);
if (violations.length) {
    violations.forEach(v => console.error(v));
    process.exit(1);
}

const SECTION_LABELS = { runtime: 'runtime', assets: 'asset' };

// Many packages ship byte-identical license boilerplate; render each unique
// text once and let the other packages reference it (roughly a third of the
// page would otherwise be duplicate <pre> blocks)
const licenseTextIds = new Map(); // text -> { id, owner }
for (let pkg of list) {
    if (pkg.licenseText && !licenseTextIds.has(pkg.licenseText)) {
        licenseTextIds.set(pkg.licenseText, { id: `lic-${licenseTextIds.size + 1}`, owner: pkg });
    }
}

function renderPackage(pkg) {
    let badges = [`<span class="badge">${he.encode(pkg.license || 'unknown')}</span>`]
        .concat(pkg.sections.map(s => `<span class="badge badge-${he.encode(s)}">${he.encode(SECTION_LABELS[s] || s)}</span>`))
        .join('\n');

    let links = [];
    if (!pkg.gateExempt && pkg.version) {
        links.push(`<a href="https://npmjs.com/package/${he.encode(pkg.name)}" rel="noopener noreferrer">npm</a>`);
    }
    if (pkg.homepage) {
        links.push(`<a href="${he.encode(pkg.homepage)}" rel="noopener noreferrer">website</a>`);
    }

    let text;
    if (pkg.licenseText) {
        let shared = licenseTextIds.get(pkg.licenseText);
        text =
            shared.owner === pkg
                ? `<details id="${he.encode(shared.id)}"><summary>Show license text</summary><pre>${he.encode(pkg.licenseText)}</pre></details>`
                : `<p class="no-text">Same license text as <a href="#${he.encode(shared.id)}">${he.encode(shared.owner.name)}</a>.</p>`;
    } else {
        text = '<p class="no-text">No license file shipped with the package.</p>';
    }

    return `<li class="package">
<div class="head">
<span class="name">${he.encode(pkg.name)}</span>
<span class="version">${he.encode(pkg.version)}</span>
${badges}
<span class="links">${links.join(' ')}</span>
</div>
${text}
</li>`;
}

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EmailEngine Licenses</title>
<style>
:root { color-scheme: light dark; --bg: #f3f4f6; --card: #ffffff; --text: #1f2937; --muted: #6b7280; --border: #e5e7eb; --accent: #4c5cc5; }
@media (prefers-color-scheme: dark) { :root { --bg: #1a1c23; --card: #232530; --text: #e5e7eb; --muted: #9ca3af; --border: #374151; --accent: #7b86dc; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1rem; background: var(--bg); color: var(--text); font: 16px/1.5 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
main { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.5rem; }
.intro { color: var(--muted); }
ul { list-style: none; margin: 1.5rem 0 0; padding: 0; display: grid; gap: 0.75rem; }
.package { background: var(--card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1rem; }
.head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.5rem; }
.name { font-weight: 600; }
.version { color: var(--muted); font-size: 0.875rem; }
.badge { border: 1px solid var(--border); border-radius: 0.25rem; padding: 0 0.4rem; font-size: 0.75rem; color: var(--muted); }
.badge-assets { color: var(--accent); border-color: var(--accent); }
.links { margin-left: auto; font-size: 0.875rem; }
a { color: var(--accent); }
details { margin-top: 0.5rem; }
summary { cursor: pointer; color: var(--muted); font-size: 0.875rem; }
pre { background: var(--bg); border-radius: 0.5rem; padding: 1rem; overflow-x: auto; white-space: pre-wrap; font-size: 0.75rem; }
.no-text { color: var(--muted); font-size: 0.875rem; margin: 0.5rem 0 0; }
</style>
</head>
<body>
<main>
<h1>EmailEngine v${he.encode(packageData.version)}</h1>
<p class="intro">EmailEngine includes code from the following open source packages. Entries marked <em>asset</em> are build-time packages whose output is embedded in the UI assets, or bundled fonts and scripts.</p>
<ul>
${list.map(renderPackage).join('\n')}
</ul>
</main>
</body>
</html>
`;

const outFile = path.join(__dirname, 'static', 'licenses.html');
fs.writeFileSync(outFile, html);

const missingText = list.filter(p => !p.licenseText).map(p => p.name);
console.log(`Wrote ${list.length} packages to ${path.relative(__dirname, outFile)}`);
if (missingText.length) {
    console.log(`No license file found for: ${missingText.join(', ')}`);
}
