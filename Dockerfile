FROM --platform=${BUILDPLATFORM} node:lts-alpine
ARG TARGETPLATFORM
ARG TARGETARCH
ARG TARGETVARIANT
RUN printf "I'm building for TARGETPLATFORM=${TARGETPLATFORM}" \
    && printf ", TARGETARCH=${TARGETARCH}" \
    && printf ", TARGETVARIANT=${TARGETVARIANT} \n" \
    && printf "With uname -s : " && uname -s \
    && printf "and  uname -m : " && uname -mm

RUN apk add --no-cache dumb-init

WORKDIR /emailengine
COPY . .

RUN npm install --omit=dev
RUN npm run prepare-docker
RUN chmod +x ./update-info.sh
RUN ./update-info.sh

ENV EENGINE_APPDIR=/emailengine
ENV EENGINE_HOST=0.0.0.0
ENV EENGINE_API_PROXY=true

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD node ${EENGINE_APPDIR}/server.js