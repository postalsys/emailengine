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
cp node_modules/ace-builds/src-min/worker-html.js static/js/ace/
cp node_modules/ace-builds/src-min/worker-json.js static/js/ace/
cp node_modules/ace-builds/src-min/worker-javascript.js static/js/ace/
cp node_modules/ace-builds/src-min/snippets/javascript.js static/js/ace/snippets
cp node_modules/ace-builds/src-min/snippets/markdown.js static/js/ace/snippets
cp node_modules/ace-builds/src-min/ext-searchbox.js static/js/ace/ext-searchbox.js

wget https://developers.google.com/static/search/apis/ipranges/special-crawlers.json -O data/google-crawlers.json
node -e 'console.log("Google crawlers updated: "+require("./data/google-crawlers.json").creationTime);'

# brew install gh
# gh auth login
# gh ext install advanced-security/gh-sbom
gh sbom -c -l > sbom.json