#!/usr/bin/env bash
#
# Smoke test the EmailEngine CLI inside a built image.
#
# The Dockerfile copies an explicit allowlist of root-level files rather than `COPY . .`, so a CLI
# subcommand that dispatches to one (e.g. `scan` -> ../scan.js, `encrypt` -> ../encrypt.js) can be
# missing from the image while the build and the server both stay green - CMD only runs server.js.
# Both `scan` and `encrypt` shipped broken that way. Exercising the commands catches it regardless of
# how the module is referenced, which a source-level check cannot.
#
# Runs against a locally-loaded image (see the workflows) BEFORE the multi-arch push, so a broken
# image is never published - the previous version smoke tested the already-pushed image and could
# only detect the regression, not prevent shipping it.
#
# Usage: docker-smoke-test.sh <image-ref>
set -euo pipefail

image="${1:?usage: docker-smoke-test.sh <image-ref>}"
status=0

# Only the subcommands that dispatch to a root-level module can exercise the allowlist; everything
# else resolves out of lib/ or node_modules. This list is a runtime spot-check, not the completeness
# authority - test/dockerfile-cli-modules-test.js derives the full set of root-level requires from
# bin/emailengine.js and fails if any is not COPYed. Add new root-dispatching subcommands here too.
for cmd in scan encrypt; do
    # These subcommands need Redis or arguments and are expected to exit non-zero; we only assert the
    # module resolved. Capture the exit code explicitly (no `|| true`, which would mask a container
    # that never started) so a docker/exec failure - exit >=125 - is treated as a failure, not a pass.
    out=$(docker run --rm --entrypoint node "$image" bin/emailengine.js "$cmd" 2>&1) && rc=0 || rc=$?

    if [ "$rc" -ge 125 ]; then
        echo "::error::container failed to start for 'emailengine $cmd' (exit $rc)"
        printf '%s\n' "$out"
        status=1
        continue
    fi

    if grep -q "Cannot find module" <<<"$out"; then
        echo "::error::emailengine $cmd cannot resolve its module inside the image"
        printf '%s\n' "$out"
        status=1
    fi
done

exit $status
