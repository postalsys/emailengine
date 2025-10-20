#  node:22.13.1-alpine
FROM --platform=${TARGETPLATFORM} node@sha256:e2b39f7b64281324929257d0f8004fb6cb4bf0fdfb9aa8cedb235a766aec31da

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
COPY LICENSE_EMAILENGINE.txt LICENSE_EMAILENGINE.txt
COPY package.json package.json
COPY package-lock.json package-lock.json
COPY sbom.json sbom.json
COPY server.js server.js

RUN mkdir -p .git/refs/heads
COPY .git/refs/heads/master .git/refs/heads/master

COPY update-info.sh update-info.sh

RUN npm ci --omit=dev
RUN npm run prepare-docker
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
