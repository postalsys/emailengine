#!/bin/bash

export EENGINE_PORT=5678

npm start > /dev/null 2>&1 &
sleep 5
curl -s "http://127.0.0.1:${EENGINE_PORT}/swagger.json" > swagger.json
pkill emailengine