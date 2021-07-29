FROM node:lts-alpine

RUN apk add --no-cache dumb-init

WORKDIR /emailengine
COPY . .

RUN npm install --production

ENV EENGINE_APPDIR=/emailengine \
    EENGINE_CONFIG=/emailengine/config/default.toml \
    CMD_ARGS=""

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD node ${EENGINE_APPDIR}/server.js --config=${EENGINE_CONFIG} --api.host="0.0.0.0" ${CMD_ARGS}
