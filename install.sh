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

if [ "$DOMAIN_NAME" = "help" ]; then
	show_info
    exit
fi

if [ "$DOMAIN_NAME" = "-h" ]; then
	show_info
    exit
fi

echo

echo "NB! This install script works on public-facing servers, do not run it on local instances."
echo "The installer tries to provision an HTTPS certificate, and the process will fail if the server
is inaccessible from the public web.
"
read -n 1 -s -r -p "Press any key to continue..."
echo "
"

if ! [ -x `command -v curl` ]; then
    apt-get update
    apt-get install curl -q -y
    echo ""
fi

if [[ -z $DOMAIN_NAME ]]; then

    echo "Enter the domain name for your new EmailEngine installation."
    echo "(ex. example.com or test.example.com)"
    echo "Leave empty to autogenerate a domain name."

    while [ -z "$DOMAIN_NAME" ]
    do
        #echo -en "\n"
        read -p "Domain/Subdomain name: " DOMAIN_NAME

        if [ -z "$DOMAIN_NAME" ]
        then
            DOMAIN_NAME=$(curl --silent --fail -XPOST "https://api.nodemailer.com/autoassign" -H "Content-Type: application/json" -d '{
                "prefix": "engine",
                "version": "1",
                "requestor": "install"
            }')
        fi
    done

fi

echo "Using the domain name \"${DOMAIN_NAME}\" for this installation."

# Prepare Caddy
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list

# Install Redis and Caddy and required tools
apt-get update
apt-get install redis-server caddy wget openssl -q -y

# Generate secure credentials
REDIS_PASSWORD=$(openssl rand -base64 32)
EENGINE_SECRET=$(openssl rand -hex 32)

# Configure Redis for production use
systemctl stop redis-server

# Backup original Redis config
cp /etc/redis/redis.conf /etc/redis/redis.conf.backup

# Configure Redis with authentication and production settings
cat >> /etc/redis/redis.conf <<EOF

# EmailEngine production configuration
requirepass $REDIS_PASSWORD
maxmemory-policy noeviction
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
EOF

# Start Redis with new configuration
systemctl start redis-server
systemctl enable redis-server

# Just in case the installation does not start Caddy already
systemctl enable caddy
systemctl start caddy

# Download and extract EmailEngine executable
TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'ee')
cd $TMPDIR
if ! [ -x `command -v wget` ]; then
    if ! [ -x `command -v curl` ]; then
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

# Create dedicated user for EmailEngine
if ! id -u emailengine >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /opt/emailengine -m emailengine
fi

# Set proper ownership
chown emailengine:emailengine /opt/emailengine

# Create unit file for EmailEngine
echo "[Unit]
Description=EmailEngine
After=redis-server

[Service]
# Configure environment variables
Environment=\"EENGINE_REDIS=redis://:${REDIS_PASSWORD}@127.0.0.1:6379/8\"
Environment=\"EENGINE_PORT=3000\"
Environment=\"EENGINE_SECRET=${EENGINE_SECRET}\"
Environment=\"EENGINE_API_PROXY=true\"
Environment=\"EENGINE_WORKERS=8\"
Environment=\"EENGINE_LOG_LEVEL=info\"
# Triggers install script specific upgrade instructions
Environment=\"EENGINE_INSTALL_SCRIPT=true\"

# Folder where EmailEngine executable is located
WorkingDirectory=/opt

# EmailEngine runs as dedicated user
User=emailengine
Group=emailengine

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

# Create Caddyfile with security headers
echo "
:80 {
  redir https://${DOMAIN_NAME}{uri}
}

${DOMAIN_NAME} {
  reverse_proxy localhost:3000 {
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto {scheme}
  }
  
  header {
    Strict-Transport-Security \"max-age=31536000; includeSubDomains\"
    X-Frame-Options \"SAMEORIGIN\"
    X-Content-Type-Options \"nosniff\"
    X-XSS-Protection \"1; mode=block\"
    Referrer-Policy \"strict-origin-when-cross-origin\"
  }
  
  # Request size limit for email operations
  request_body {
    max_size 100MB
  }
}" > /etc/caddy/Caddyfile

# Create upgrade script
cat > '/opt/upgrade-emailengine.sh' <<'EOL'
#!/bin/bash

set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

OLD_VERSION=`/opt/emailengine -v`

TMPDIR=$(mktemp -d -t ci-XXXXXXXXXX)

cd "$TMPDIR"
wget https://github.com/postalsys/emailengine/releases/latest/download/emailengine.tar.gz
tar xzf emailengine.tar.gz
rm -rf emailengine.tar.gz

NEW_VERSION=`./emailengine -v`

if [ "$OLD_VERSION" = "$NEW_VERSION" ]; then
    rm -rf "$TMPDIR"
    echo "Nothing to upgrade, already running $NEW_VERSION"
else
    mv emailengine /opt
    rm -rf "$TMPDIR"
    chmod +x /opt/emailengine
    chown emailengine:emailengine /opt/emailengine
    systemctl restart emailengine

    echo "Upgraded EmailEngine"
    echo "  - was: $OLD_VERSION"
    echo "  - now: $NEW_VERSION"
fi
EOL
chmod +x /opt/upgrade-emailengine.sh


systemctl reload caddy

printf "Waiting for the web server to start up.."
until $(curl --output /dev/null --silent --fail https://${DOMAIN_NAME}/); do
    printf '.'
    sleep 2
done
echo "."

# Save credentials to a secure file
cat > /root/emailengine-credentials.txt <<EOF
===========================================
EmailEngine Installation Credentials
===========================================

Domain: https://${DOMAIN_NAME}/

Redis Password: ${REDIS_PASSWORD}
Encryption Secret: ${EENGINE_SECRET}

IMPORTANT: Save these credentials securely!
They cannot be recovered if lost.

Systemd service: emailengine
Service user: emailengine
Redis database: 8

Commands:
  Status: systemctl status emailengine
  Logs: journalctl -u emailengine -f
  Restart: systemctl restart emailengine
  Upgrade: /opt/upgrade-emailengine.sh

Monitoring:
  Redis memory: redis-cli -a '${REDIS_PASSWORD}' INFO memory
  Service health: curl http://localhost:3000/health
===========================================
EOF

chmod 600 /root/emailengine-credentials.txt

echo ""
echo "========================================="
echo "Installation complete!"
echo "========================================="
echo ""
echo "Access your EmailEngine installation at:"
echo "  https://${DOMAIN_NAME}/"
echo ""
echo "IMPORTANT: Credentials have been saved to:"
echo "  /root/emailengine-credentials.txt"
echo ""
echo "This file contains your Redis password and encryption secret."
echo "Store these credentials securely - they cannot be recovered!"
echo ""
echo "To upgrade EmailEngine in the future:"
echo "  /opt/upgrade-emailengine.sh"
echo ""
echo "To monitor Redis memory usage:"
echo "  redis-cli -a 'YOUR_REDIS_PASSWORD' INFO memory"
echo ""