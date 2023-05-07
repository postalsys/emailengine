#!/bin/sh

COMMIT_HASH=$(cat .git/refs/heads/master)
TIMESTAMP=$(node -e 'console.log(Date.now())')
cat >version-info.json <<EOL
{
    "commit": "${COMMIT_HASH}",
    "time": "${TIMESTAMP}"
}
EOL
