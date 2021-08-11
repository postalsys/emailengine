FROM node:lts-alpine

RUN apk add --no-cache dumb-init

WORKDIR /emailengine
COPY . .

RUN npm install --production

ENV EENGINE_APPDIR=/emailengine
ENV EENGINE_CONFIG=/emailengine/config/default.toml
ENV EENGINE_HOST=0.0.0.0
ENV EENGINE_SMTP_HOST=0.0.0.0
ENV CMD_ARGS=""

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD node ${EENGINE_APPDIR}/server.js --config=${EENGINE_CONFIG} ${CMD_ARGS}
