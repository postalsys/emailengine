#!/bin/sh

# Resolve the commit hash for version-info.json:
#  1. EE_COMMIT_HASH is the explicit override, and the only source the Docker
#     image build and the release builds have - neither runs in a checkout with
#     a usable .git. The Dockerfile requires it; here it is optional
#  2. git rev-parse works in any normal checkout, also when refs are packed;
#     the toplevel check makes sure the hash comes from this repository and
#     not from an unrelated parent repository when this directory is not a
#     git repository itself
#
# There used to be a third branch reading .git/refs/heads/master directly. It
# existed only for the Docker build, which copied that one file into the context;
# the build now takes the arg instead, so nothing could reach it. It was also
# doubly unreliable - hardcoded to one branch name, and a fresh clone packs its
# refs away so the file need not exist at all.
#
# An unresolved hash is left empty rather than failing, because the remaining
# callers that supply nothing (render.yaml) still want a version-info.json.
if [ -n "$EE_COMMIT_HASH" ]; then
    COMMIT_HASH="$EE_COMMIT_HASH"
elif [ "$(git rev-parse --show-toplevel 2>/dev/null)" = "$(pwd -P)" ] && git rev-parse HEAD >/dev/null 2>&1; then
    COMMIT_HASH=$(git rev-parse HEAD)
else
    COMMIT_HASH=""
fi

TIMESTAMP=$(node -e 'console.log(Date.now())')
cat >version-info.json <<EOL
{
    "commit": "${COMMIT_HASH}",
    "time": "${TIMESTAMP}"
}
EOL
