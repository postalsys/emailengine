FROM node:lts-alpine

RUN apk add --no-cache dumb-init

WORKDIR /imapapi
COPY . .

RUN npm install --production

ENV IMAPAPI_APPDIR=/imapapi \
    IMAPAPI_CONFIG=/imapapi/config/default.toml \
    CMD_ARGS=""

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD node ${IMAPAPI_APPDIR}/server.js --config=${IMAPAPI_CONFIG} --api.host="0.0.0.0" ${CMD_ARGS}
