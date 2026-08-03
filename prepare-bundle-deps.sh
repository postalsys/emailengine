#!/bin/sh

# Fixups applied to the production node_modules tree before pkg bundles it.
#
# pkg walks every file a package's `exports` map points at and runs it through esbuild.
# A file esbuild transforms to nothing leaves pkg dereferencing an undefined result, and
# it dies with "Cannot read properties of undefined (reading 'tokens')" naming whichever
# of our own files happened to pull the package in - which points at the wrong place
# entirely. Fixed upstream in neither pkg 6.21 nor 6.22.
#
# Run from npm run build-source, after `npm ci --omit=dev` has produced the tree that
# actually gets bundled.

set -e

# @standard-schema/spec (joi >=18) is a types-only package: its runtime export is
# literally `{}` (see dist/index.cjs) and joi names it only in an `import type` inside
# lib/index.d.ts, which TypeScript erases. Its ESM entry point dist/index.js is therefore
# a 0-byte file, which is the one pkg cannot swallow.
#
# The file is restored to what an empty ES module should look like rather than deleted:
# the package stays resolvable, so a future joi that does require it at runtime keeps
# working instead of failing inside a shipped binary.
EMPTY_ESM="node_modules/@standard-schema/spec/dist/index.js"
if [ -f "$EMPTY_ESM" ] && [ ! -s "$EMPTY_ESM" ]; then
    echo "export {};" >"$EMPTY_ESM"
    echo "patched empty ESM entry point: $EMPTY_ESM"
fi
