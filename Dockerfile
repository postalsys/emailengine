# Pinned by tag AND digest: the digest is what actually gets pulled, so a rebuild of an old commit
# resolves the same Node layer, and the tag next to it keeps the line readable and lets Dependabot
# parse it (it does not follow an ARG-defined image). Both stages must stay on the same pin.
#
# The pin has to be moved deliberately - it sat on node:22.13.1-alpine for 19 months, which is how
# the image ended up shipping 21 unpatched Alpine CVEs. `apk upgrade` below covers the drift between
# pin bumps, and the docker_scan job in .github/workflows/test.yml fails the build once a fix for a
# HIGH/CRITICAL exists but is not picked up.

# Build stage. Everything that needs a package manager, a shell or a writable source tree happens
# here; the runtime stage below copies out only the finished tree, so npm and its dependencies never
# reach the published image. npm accounted for 38 of the 59 HIGH/CRITICAL findings in the old image
# (a vendored tar, pacote, sigstore, minimatch) and nothing at runtime ever invokes it.
FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS builder

ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETARCH
ARG TARGETVARIANT
RUN printf "I'm building for TARGETPLATFORM=${TARGETPLATFORM}" \
    && printf ", BUILDPLATFORM=${BUILDPLATFORM}" \
    && printf ", TARGETARCH=${TARGETARCH}" \
    && printf ", TARGETVARIANT=${TARGETVARIANT} \n" \
    && printf "With uname -s : " && uname -s \
    && printf "and  uname -m : " && uname -mm

WORKDIR /emailengine

# Install dependencies before copying any source. npm ci is by far the slowest step in this
# build - it runs under QEMU emulation for the non-native architecture - and Docker invalidates
# every layer below a changed one. With the sources copied first, an edit to any file busted
# this layer and re-ran the whole install; keeping it above them means it is only re-run when
# the lockfile actually changes.
COPY package.json package.json
COPY package-lock.json package-lock.json
RUN npm ci --omit=dev

# Copy app folders
COPY bin bin
COPY config config
COPY data data
COPY lib lib
COPY static static
COPY translations translations
COPY views views
COPY workers workers

# Copy required root level files
# NB: bin/emailengine.js requires ../encrypt and ../scan for the `encrypt` and `scan`
# subcommands. This COPY list is an allowlist, so any root-level module the CLI dispatches
# to must be named here or the command fails with MODULE_NOT_FOUND inside the container.
COPY LICENSE_EMAILENGINE.txt LICENSE_EMAILENGINE.txt
COPY encrypt.js encrypt.js
COPY sbom.json sbom.json
COPY scan.js scan.js
COPY server.js server.js

RUN mkdir -p .git/refs/heads
COPY .git/refs/heads/master .git/refs/heads/master

# version-info.json is generated here and the inputs are dropped again, so neither the git ref nor
# the script itself ends up in the runtime image.
COPY update-info.sh update-info.sh
RUN chmod +x ./update-info.sh \
    && ./update-info.sh \
    && rm -rf .git update-info.sh

# Runtime stage.
FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3

# `apk upgrade` patches the Alpine packages that the base image itself lags on - at the time of
# writing node:24-alpine still carries an openssl below 3.5.8-r0. dumb-init reaps zombies as PID 1.
# npm is removed outright: it is a build-time tool, and leaving it in only adds scan surface.
RUN apk add --no-cache dumb-init \
    && apk upgrade --no-cache \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Create a non-root user and group
RUN addgroup -S emailenginegroup && adduser -S emailengineuser -G emailenginegroup

WORKDIR /emailengine

COPY --from=builder --chown=emailengineuser:emailenginegroup /emailengine /emailengine

RUN node -e "console.log('node arch: ' + os.arch())"
RUN node -e "console.log(process.versions)"

# Switch to non-root user
USER emailengineuser

ENV EENGINE_HOST=0.0.0.0
ENV EENGINE_API_PROXY=true

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "/emailengine/server.js"]
