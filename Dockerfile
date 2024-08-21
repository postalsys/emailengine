FROM --platform=${BUILDPLATFORM} node:20.16.0-alpine
ARG TARGETPLATFORM
ARG TARGETARCH
ARG TARGETVARIANT
RUN printf "I'm building for TARGETPLATFORM=${TARGETPLATFORM}" \
    && printf ", TARGETARCH=${TARGETARCH}" \
    && printf ", TARGETVARIANT=${TARGETVARIANT} \n" \
    && printf "With uname -s : " && uname -s \
    && printf "and  uname -m : " && uname -mm

RUN apk add --no-cache dumb-init

# Create a non-root user and group
RUN addgroup -S emailenginegroup && adduser -S emailengineuser -G emailenginegroup

WORKDIR /emailengine
COPY . .

RUN npm install --omit=dev
RUN npm run prepare-docker
RUN chmod +x ./update-info.sh
RUN ./update-info.sh

# Ensure permissions are set correctly for the non-root user
RUN chown -R emailengineuser:emailenginegroup /emailengine

# Switch to non-root user
USER emailengineuser

ENV EENGINE_APPDIR=/emailengine
ENV EENGINE_HOST=0.0.0.0
ENV EENGINE_API_PROXY=true

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD node ${EENGINE_APPDIR}/server.js
