#!/bin/bash

export API_PORT=5678

npm start > /dev/null 2>&1 &
sleep 5
curl -s "http://127.0.0.1:${API_PORT}/swagger.json" > swagger.json
pkill imapapi