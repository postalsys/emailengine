#  node:24.18.0-alpine
FROM --platform=${TARGETPLATFORM} node@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd

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

RUN apk add --no-cache dumb-init

# Create a non-root user and group
RUN addgroup -S emailenginegroup && adduser -S emailengineuser -G emailenginegroup

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

COPY update-info.sh update-info.sh
RUN chmod +x ./update-info.sh
RUN ./update-info.sh

# Ensure permissions are set correctly for the non-root user
RUN chown -R emailengineuser:emailenginegroup /emailengine

RUN node -e "console.log('node arch: ' + os.arch())"
RUN node -e "console.log(process.versions)"

# Switch to non-root user
USER emailengineuser

ENV EENGINE_HOST=0.0.0.0
ENV EENGINE_API_PROXY=true

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "/emailengine/server.js"]
