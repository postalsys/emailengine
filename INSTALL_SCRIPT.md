# EmailEngine Installation Script

The `install.sh` script provides automated installation of EmailEngine on Debian/Ubuntu servers with production-ready security configurations.

## Prerequisites

-   **Public-facing server** with a valid domain name
-   **Root access** to the server
-   **Debian/Ubuntu** based Linux distribution
-   **Open ports**: 80 and 443 (for HTTPS)
-   Minimum **4GB RAM**, recommended **8GB+**

## Quick Installation

```bash
curl -s https://raw.githubusercontent.com/postalsys/emailengine/master/install.sh | bash -s yourdomain.com
```

Or download and run:

```bash
wget https://raw.githubusercontent.com/postalsys/emailengine/master/install.sh
chmod +x install.sh
sudo ./install.sh yourdomain.com
```

## What the Script Does

### Security Features

1. **Generates secure credentials**:

    - Random 32-byte Redis password
    - Random 32-character encryption secret

2. **Configures Redis securely**:

    - Enables authentication with strong password
    - Sets `noeviction` policy (database mode)
    - Enables persistence (AOF + RDB)
    - Optimizes for production use

3. **Creates dedicated user**:

    - Runs EmailEngine as `emailengine` user (not root)
    - Isolated from other services

4. **Configures Caddy with security headers**:
    - Automatic HTTPS with Let's Encrypt
    - HSTS, X-Frame-Options, CSP headers
    - 100MB request size limit

### Components Installed

-   **EmailEngine**: Latest release from GitHub
-   **Redis**: Database with authentication
-   **Caddy**: Web server with automatic HTTPS
-   **Systemd service**: Auto-start and monitoring

## Post-Installation

### Credentials

After installation, credentials are saved to:

```
/root/emailengine-credentials.txt
```

**IMPORTANT**: Save these credentials securely! They include:

-   Redis password
-   Encryption secret
-   Cannot be recovered if lost

### Useful Commands

```bash
# Check service status
systemctl status emailengine

# View logs
journalctl -u emailengine -f

# Restart service
systemctl restart emailengine

# Monitor Redis memory
redis-cli -a 'YOUR_REDIS_PASSWORD' INFO memory

# Check health
curl http://localhost:3000/health

# Upgrade EmailEngine
/opt/upgrade-emailengine.sh
```

### File Locations

-   **EmailEngine binary**: `/opt/emailengine`
-   **Systemd service**: `/etc/systemd/system/emailengine.service`
-   **Caddy config**: `/etc/caddy/Caddyfile`
-   **Redis config**: `/etc/redis/redis.conf`
-   **Credentials**: `/root/emailengine-credentials.txt`
-   **Upgrade script**: `/opt/upgrade-emailengine.sh`

## Monitoring

Since Redis has no memory limits (database mode), monitor memory usage:

```bash
# Check Redis memory usage
redis-cli -a 'YOUR_REDIS_PASSWORD' INFO memory | grep used_memory_human

# Monitor all services
docker stats  # If using Docker
htop          # System resources
```

## Backup Recommendations

### Redis Data

Redis data is stored in `/var/lib/redis/`. Set up regular backups:

```bash
# Create backup
redis-cli -a 'YOUR_REDIS_PASSWORD' BGSAVE

# Backup files to copy:
/var/lib/redis/dump.rdb
```

### Automated Backup Script

Create `/opt/backup-emailengine.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/backup/emailengine"
DATE=$(date +%Y%m%d-%H%M%S)
REDIS_PASSWORD="YOUR_REDIS_PASSWORD"

mkdir -p $BACKUP_DIR

# Trigger Redis save
redis-cli -a "$REDIS_PASSWORD" BGSAVE
sleep 5

# Backup Redis data
tar czf $BACKUP_DIR/redis-$DATE.tar.gz /var/lib/redis/

# Keep 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

Add to crontab:

```bash
0 2 * * * /opt/backup-emailengine.sh
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u emailengine -n 50

# Verify Redis is running
systemctl status redis-server

# Test Redis connection
redis-cli -a 'YOUR_REDIS_PASSWORD' ping
```

### Certificate Issues

If HTTPS certificate fails:

1. Ensure domain points to server
2. Ports 80 and 443 are open
3. Check Caddy logs: `journalctl -u caddy`

### High Memory Usage

```bash
# Check Redis memory
redis-cli -a 'YOUR_REDIS_PASSWORD' INFO memory

# System memory
free -h

# Process memory
ps aux | grep -E 'emailengine|redis'
```

## Security Notes

1. **Firewall**: Only ports 80, 443, and SSH should be open
2. **Updates**: Run `/opt/upgrade-emailengine.sh` regularly
3. **Monitoring**: Set up alerts for high memory usage
4. **Backups**: Test restore procedures regularly

## Limitations

-   Script requires public-facing server (for HTTPS certificates)
-   Only works on Debian/Ubuntu systems
-   Not suitable for local/development installations
-   Requires root access for installation

For development or Docker deployments, see [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md).
