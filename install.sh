#!/bin/bash

set -e

DOMAIN_NAME=$1
EMAIL_ADDRESS=$2

APP_URL="https://github.com/postalsys/emailengine/releases/latest/download/emailengine.tar.gz"

show_info () {
    echo "Usage: $0 <domain-name> <email-address>"
    echo "Where"
    echo " <domain-name> is the domain name for EmailEngine, eg. \"example.com\""
    echo " <email-address> is your email address, needed to generate HTTPS certs. Must be valid."
}

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    show_info
    exit 1
fi

if [[ -z $DOMAIN_NAME ]]; then
    show_info
    exit
fi

if [[ -z $EMAIL_ADDRESS ]]; then
    show_info
    exit
fi

if [ $DOMAIN_NAME = "help" ]; then
	show_info
    exit
fi

# Install Redis and Nginx
apt-get update
apt-get install redis-server nginx wget -q -y

TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'ee')

cd $TMPDIR

# Download EmailEngine executable
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

# Setup certs for Nginx

openssl req -subj "/CN=${DOMAIN_NAME}/O=EmailEngine./C=US" -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout privkey.pem -out fullchain.pem
chmod 0600 privkey.pem
mv privkey.pem /etc/ssl/private/emailengine-privkey.pem 
mv fullchain.pem /etc/ssl/certs/emailengine-fullchain.pem

rm -rf $TMPDIR

# Create unit file
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

echo "server {
    listen 80;
    listen 443 ssl http2;

    server_name ${DOMAIN_NAME};

    ssl_certificate_key /etc/ssl/private/emailengine-privkey.pem;
    ssl_certificate /etc/ssl/certs/emailengine-fullchain.pem;

    location / {
        client_max_body_size 50M;
        proxy_http_version 1.1;
        proxy_redirect off;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Scheme \$scheme;
        proxy_set_header Host \$http_host;
        proxy_set_header X-NginX-Proxy true;
        proxy_pass http://127.0.0.1:3000; # <- use EmailEngine's HTTP port
    }

    # Enforce HTTPS
    if (\$scheme != \"https\") {
        return 301 https://\$host\$request_uri;
    }
}" > /etc/nginx/sites-available/emailengine.conf

if [ ! -f "/etc/nginx/sites-enabled/emailengine.conf" ]
then
    ln -s /etc/nginx/sites-available/emailengine.conf /etc/nginx/sites-enabled/emailengine.conf
fi

# check config
nginx -t

cd
curl https://get.acme.sh | sh -s email="${EMAIL_ADDRESS}"

/root/.acme.sh/acme.sh --issue --nginx --server letsencrypt \
    -d "${DOMAIN_NAME}" \
    --key-file       /etc/ssl/private/emailengine-privkey.pem  \
    --ca-file        /etc/ssl/certs/emailengine-chain.pem \
    --fullchain-file /etc/ssl/certs/emailengine-fullchain.pem \
    --reloadcmd     "/bin/systemctl reload nginx"

echo "EmailEngine was set up"