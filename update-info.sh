#!/bin/sh

COMMIT_HASH=$(git rev-parse HEAD)
TIMESTAMP=$(node -e 'console.log(Date.now())')
cat >version-info.json <<EOL
{
    "commit": "${COMMIT_HASH}",
    "time": "${TIMESTAMP}"
}
EOL
