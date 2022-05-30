#!/bin/bash

set -e

DOMAIN_NAME=$1

APP_URL="https://github.com/postalsys/emailengine/releases/latest/download/emailengine.tar.gz"

show_info () {
    echo "Usage: $0 <domain-name>"
    echo "Where"
    echo " <domain-name> is the domain name for EmailEngine, eg. \"example.com\""
}

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    show_info
    exit 1
fi

if [[ -z $DOMAIN_NAME ]]; then

    echo "Enter the domain name for your new EmailEngine installation."
    echo "(ex. example.com or test.example.com)"

    while [ -z "$DOMAIN_NAME" ]
    do
        #echo -en "\n"
        read -p "Domain/Subdomain name: " DOMAIN_NAME
    done

fi

if [ $DOMAIN_NAME = "help" ]; then
	show_info
    exit
fi

# Prepare Caddy
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list

# Install Redis and Caddy
apt-get update
apt-get install redis-server caddy wget -q -y

# Just in case the installation does not start Caddy already
systemctl enable caddy
systemctl start caddy

# Download and extract EmailEngine executable
TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'ee')
cd $TMPDIR
if ! [ -x `command -v wget` ]; then
    if ! [ -x `command -v wget` ]; then
        echo "Can not download application"
        exit 1
    else
        curl "$APP_URL" -L -o emailengine.tar.gz
    fi
else
    # use wget do download EmailEngine
    wget "$APP_URL"
fi

tar xzf emailengine.tar.gz
rm -rf emailengine.tar.gz
mv emailengine /opt
chmod +x /opt/emailengine

rm -rf $TMPDIR

# Create unit file for EmailEngine
echo "[Unit]
Description=EmailEngine
After=redis-server

[Service]
# Configure environment variables
Environment=\"EENGINE_REDIS=redis://127.0.0.1:6379/8\"
Environment=\"EENGINE_PORT=3000\"

# Folder where EmailEngine executable is located
WorkingDirectory=/opt

# EmailEngine does not require any special privileges
User=www-data
Group=www-data

# Run the EmailEngine executable
ExecStart=/opt/emailengine

Type=simple
Restart=always

SyslogIdentifier=emailengine

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/emailengine.service

systemctl daemon-reload
systemctl enable emailengine
systemctl restart emailengine

# Create Caddyfile
echo "
:80 {
  redir https://${DOMAIN_NAME}{uri}
}

${DOMAIN_NAME} {
  reverse_proxy localhost:3000
}" > /etc/caddy/Caddyfile

systemctl reload caddy

printf "Waiting for the web server to start up.."
until $(curl --output /dev/null --silent --fail https://${DOMAIN_NAME}/); do
    printf '.'
    sleep 2
done
echo "."

echo ""
echo "Installation complete."
echo "Access your new EmailEngine installation in a browser at https://${dom}/"
echo ""