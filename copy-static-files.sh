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

# Both JSON artifacts below are refreshed from the network and are committed, so a failed fetch
# must not be allowed to damage the copy already in the tree. A plain `> file` redirect truncates
# before the command runs, which is how a GitHub 500 once left a zero-byte sbom.json behind - and
# under `set -e` it also aborts the rest of this script, silently skipping the licence and gettext
# regeneration that npm run update chains after it. Each fetch therefore lands in a sibling temp
# file, is checked for being valid JSON, and only then replaces the committed one. The temp file
# is created next to its target rather than in $TMPDIR so the move is a rename within the same
# filesystem, never a copy that could be interrupted half-written.
fetch_json() {
    local target="$1"
    shift
    local tmp
    tmp=$(mktemp "${target}.XXXXXX")
    if "$@" > "$tmp" && node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$tmp"; then
        mv "$tmp" "$target"
    else
        rm -f "$tmp"
        echo "WARNING: failed to refresh ${target}, keeping the previous copy" >&2
    fi
}

fetch_json data/google-crawlers.json wget -q -O - https://developers.google.com/static/crawling/ipranges/special-crawlers.json
node -e 'console.log("Google crawlers updated: "+require("./data/google-crawlers.json").creationTime);'

# brew install gh
# gh auth login
# gh ext install advanced-security/gh-sbom
# gh sbom -c -l > sbom.json
fetch_json sbom.json gh sbom