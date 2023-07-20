FROM node:lts-alpine

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