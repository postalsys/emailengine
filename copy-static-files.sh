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
cp node_modules/ace-builds/src-min/theme-xcode.js static/js/ace/
cp node_modules/ace-builds/src-min/theme-kuroir.js static/js/ace/
# dark-theme counterparts applied by uiAceEditor/uiAcePreview (static/js/ui.js)
cp node_modules/ace-builds/src-min/theme-tomorrow_night.js static/js/ace/
cp node_modules/ace-builds/src-min/theme-tomorrow_night_eighties.js static/js/ace/
cp node_modules/ace-builds/src-min/worker-html.js static/js/ace/
cp node_modules/ace-builds/src-min/worker-json.js static/js/ace/
cp node_modules/ace-builds/src-min/worker-javascript.js static/js/ace/
cp node_modules/ace-builds/src-min/snippets/javascript.js static/js/ace/snippets
cp node_modules/ace-builds/src-min/snippets/markdown.js static/js/ace/snippets
cp node_modules/ace-builds/src-min/ext-searchbox.js static/js/ace/ext-searchbox.js

cp node_modules/\@postalsys/ee-client/index.js static/js/ee-client.js

# FlyonUI browser bundle (vendored like ace above; committed and bundled by pkg)
cp node_modules/flyonui/flyonui.js static/js/flyonui.js

# Rebuild the compiled admin UI stylesheet (Tailwind v4 + FlyonUI)
npm run build:css

wget https://developers.google.com/static/crawling/ipranges/special-crawlers.json -O data/google-crawlers.json
node -e 'console.log("Google crawlers updated: "+require("./data/google-crawlers.json").creationTime);'

# brew install gh
# gh auth login
# gh ext install advanced-security/gh-sbom
# gh sbom -c -l > sbom.json
#
# Staged through a temp file: a plain redirect truncates sbom.json before gh runs, so a
# failing call (the dependency-graph endpoint times out with a 500 often enough) leaves an
# empty file behind and the refresh looks like it deleted the SBOM.
sbom_tmp=$(mktemp)
if gh sbom > "$sbom_tmp" && [ -s "$sbom_tmp" ]; then
    mv "$sbom_tmp" sbom.json
else
    rm -f "$sbom_tmp"
    echo "WARNING: gh sbom failed, keeping the previous sbom.json" >&2
fi