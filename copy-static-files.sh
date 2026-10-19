#!/bin/bash

set -e

rm -rf static/js/ace
mkdir -p static/js/ace/snippets
echo "This folder is autocreated, do not make any changes manually" > static/js/ace/README.txt

cp node_modules/ace-builds/src-min/ace.js static/js/ace/
cp node_modules/ace-builds/src-min/ext-language_tools.js static/js/ace/
cp node_modules/ace-builds/src-min/mode-handlebars.js static/js/ace/
cp node_modules/ace-builds/src-min/mode-html.js static/js/ace/
cp node_modules/ace-builds/src-min/mode-json.js static/js/ace/
cp node_modules/ace-builds/src-min/mode-javascript.js static/js/ace/
cp node_modules/ace-builds/src-min/mode-markdown.js static/js/ace/
cp node_modules/ace-builds/src-min/worker-html.js static/js/ace/
cp node_modules/ace-builds/src-min/worker-json.js static/js/ace/
cp node_modules/ace-builds/src-min/worker-javascript.js static/js/ace/
cp node_modules/ace-builds/src-min/snippets/javascript.js static/js/ace/snippets
cp node_modules/ace-builds/src-min/snippets/markdown.js static/js/ace/snippets
cp node_modules/ace-builds/src-min/ext-searchbox.js static/js/ace/ext-searchbox.js

# ACE stylesheets, linked by views/partials/ace_assets.hbs. That partial also puts ACE in
# strict-CSP mode, so it injects no <style> elements of its own and the admin
# Content-Security-Policy can require a nonce on every stylesheet.
mkdir -p static/js/ace/css/theme
cp node_modules/ace-builds/css/ace.css static/js/ace/css/

# The light/dark pairs uiAceEditor and uiAcePreview switch between (static/js/ui.js). Each theme
# needs its module (for the cssClass and isDark ACE reads from it) and its stylesheet.
for theme in xcode kuroir tomorrow_night tomorrow_night_eighties; do
    cp node_modules/ace-builds/src-min/theme-$theme.js static/js/ace/
    cp node_modules/ace-builds/css/theme/$theme.css static/js/ace/css/theme/
done

# The images the sheets reference. Both bases land in css/ - ace.css uses ./, a theme uses ../ -
# so one pass over the copied sheets covers them.
for image in $(grep -oh 'url("[^"]*")' static/js/ace/css/ace.css static/js/ace/css/theme/*.css | sed 's/^url("//; s/")$//; s/^\.\.\///; s/^\.\///' | sort -u); do
    cp node_modules/ace-builds/css/$image static/js/ace/css/
done

cp node_modules/\@postalsys/ee-client/index.js static/js/ee-client.js

# SimpleWebAuthn browser bundle, kept at the same version as @simplewebauthn/server (the
# devDependency exists only to be vendored here; login-passkey.js and passkey-register.js load it)
cp node_modules/\@simplewebauthn/browser/dist/bundle/index.umd.min.js static/vendor/simplewebauthn/browser.min.js

# FlyonUI browser bundle (vendored like ace above; committed and bundled by pkg)
cp node_modules/flyonui/flyonui.js static/js/flyonui.js

# Rebuild the compiled admin UI stylesheet (Tailwind v4 + FlyonUI)
npm run build:css

# The artifacts below are regenerated (mostly from the network) and are committed, so a failed fetch
# must not be allowed to damage the copy already in the tree. A plain `> file` redirect truncates
# before the command runs, which is how a GitHub 500 once left a zero-byte sbom.json behind - and
# under `set -e` it also aborts the rest of this script, silently skipping the licence and gettext
# regeneration that npm run update chains after it. Each fetch therefore lands in a sibling temp
# file, is checked for being complete (valid JSON, or a format-specific check), and only then
# replaces the committed one. The temp file is created next to its target rather than in $TMPDIR
# so the move is a rename within the same filesystem, never a copy that could be interrupted
# half-written.
#
# fetch_checked TARGET CHECK COMMAND...: CHECK is a node script that throws unless the file named
# by process.argv[1] is a complete copy of what TARGET (process.argv[2]) should hold. A CHECK that
# exits with status 3 instead says the new copy changes nothing that matters, and the committed one
# is kept without a warning.
fetch_checked() {
    local target="$1"
    local check="$2"
    shift 2
    local tmp status
    tmp=$(mktemp "${target}.XXXXXX")
    if "$@" > "$tmp" && node -e "$check" "$tmp" "$target"; then
        # mktemp creates the file 0600
        chmod 644 "$tmp"
        mv "$tmp" "$target"
    else
        status=$?
        rm -f "$tmp"
        if [ "$status" -ne 3 ]; then
            echo "WARNING: failed to refresh ${target}, keeping the previous copy" >&2
        fi
    fi
}

fetch_json() {
    local target="$1"
    shift
    fetch_checked "$target" 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$@"
}

fetch_json data/google-crawlers.json wget -q -O - https://developers.google.com/static/crawling/ipranges/special-crawlers.json
node -e 'console.log("Google crawlers updated: "+require("./data/google-crawlers.json").creationTime);'

# The Public Suffix List, read by lib/utils/public-suffix.js. Kept verbatim (it is MPL-2.0 and carries
# its own licence header), and only accepted when both sections arrived whole: a truncated list would
# not fail to parse, it would just quietly know fewer suffixes.
fetch_checked data/public_suffix_list.dat 'const t=require("fs").readFileSync(process.argv[1],"utf8");for(const m of ["===BEGIN ICANN DOMAINS===","===END ICANN DOMAINS===","===BEGIN PRIVATE DOMAINS===","===END PRIVATE DOMAINS==="])if(!t.includes(m))throw new Error("missing "+m)' wget -q -O - https://publicsuffix.org/list/public_suffix_list.dat
grep -m1 '^// VERSION:' data/public_suffix_list.dat || true

# The SBOM shipped in the binary and served at /sbom.json, generated from the installed tree by npm
# (SPDX 2.3). Runtime dependencies only: dev tooling never reaches an instance. It used to come
# from GitHub's dependency graph (gh sbom), which only knows a lockfile once it has been pushed, so
# every dependency bump needed a second update after the push to catch up. npm stamps each run with
# a new creation time and document namespace, so a copy that differs in nothing else is not taken.
fetch_checked sbom.json 'const fs=require("fs");const strip=f=>{const d=JSON.parse(fs.readFileSync(f,"utf8"));delete d.documentNamespace;delete d.creationInfo.created;return JSON.stringify(d)};const next=strip(process.argv[1]);let prev=null;try{prev=strip(process.argv[2])}catch{}if(next===prev)process.exit(3)' npm sbom --sbom-format spdx --omit dev
