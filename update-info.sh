#!/bin/sh

# Resolve the commit hash for version-info.json:
#  1. EE_COMMIT_HASH is the explicit override, set by the deploy workflow and
#     by release builds that run from a git export without a .git directory
#  2. git rev-parse works in any normal checkout, also when refs are packed;
#     the toplevel check makes sure the hash comes from this repository and
#     not from an unrelated parent repository when this directory is not a
#     git repository itself
#  3. the plain ref file is the fallback for the Docker image build, which
#     only copies .git/refs/heads/master into the build context
if [ -n "$EE_COMMIT_HASH" ]; then
    COMMIT_HASH="$EE_COMMIT_HASH"
elif [ "$(git rev-parse --show-toplevel 2>/dev/null)" = "$(pwd -P)" ] && git rev-parse HEAD >/dev/null 2>&1; then
    COMMIT_HASH=$(git rev-parse HEAD)
elif [ -f .git/refs/heads/master ]; then
    COMMIT_HASH=$(cat .git/refs/heads/master)
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
