# EmailEngine Docker Deployment Guide

This guide covers everything from local development to production deployment of EmailEngine using Docker.

## Table of Contents

-   [Quick Start](#quick-start)
-   [Configuration](#configuration)
-   [Production Deployment](#production-deployment)
-   [Operations & Maintenance](#operations--maintenance)
-   [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites

-   Docker Engine 20.10.0+ and Docker Compose 2.0.0+
-   **System Requirements**:
    -   Development: 4GB RAM minimum
    -   Production: 8GB RAM minimum, 16GB+ recommended
-   **Critical Notes**:
    -   No Docker resource limits are imposed
    -   Redis has NO memory limit and uses 'noeviction' policy (database mode)
    -   **MUST monitor memory usage** to prevent system OOM
-   **Monitoring**: Use `docker stats` and Redis INFO memory regularly

### Development Setup

```bash
# Clone or download EmailEngine
git clone https://github.com/postalsys/emailengine.git
cd emailengine

# Start with development settings
cp .env.development .env
docker-compose up
```

**Access EmailEngine at http://localhost:3000**

Development mode features:

-   No authentication required
-   Services accessible from any network
-   Debug logging enabled
-   Minimal resource requirements

### Production Setup (5 minutes)

```bash
# Use automated setup script
./setup-production.sh

# Or manually:
cp .env.production .env
nano .env  # Add secure passwords (see Configuration section)
docker-compose up -d
```

Production mode features:

-   Redis authentication required
-   Services bound to localhost only
-   Optimized logging and persistence
-   Health checks and resource limits

## Configuration

EmailEngine uses a single `docker-compose.yml` that adapts based on environment variables in `.env`.

### Environment Templates

| File               | Purpose               | Security | Use Case             |
| ------------------ | --------------------- | -------- | -------------------- |
| `.env.development` | Local development     | None     | Testing, development |
| `.env.production`  | Production deployment | Full     | Live systems         |

### Key Configuration Differences

| Setting                 | Development                | Production                   |
| ----------------------- | -------------------------- | ---------------------------- |
| **Network Binding**     | `0.0.0.0` (all interfaces) | `127.0.0.1` (localhost only) |
| **Redis Password**      | None                       | Required                     |
| **Secret Key**          | Default                    | Must generate                |
| **Health Checks**       | Relaxed                    | Strict                       |
| **Logging**             | Debug                      | Info                         |
| **System Requirements** | Minimal                    | Production-grade             |

### Essential Production Variables

```bash
# Generate secure credentials
EENGINE_SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -base64 32)

# Configure in .env
EENGINE_SECRET=<generated-secret>
REDIS_PASSWORD=<generated-password>
EMAILENGINE_API_BIND=127.0.0.1  # Never expose directly

# Note: Redis has no memory limit and uses 'noeviction' policy
# This is intentional - EmailEngine uses Redis as a database
```

## Production Deployment

### Step 1: Server Preparation

```bash
# Create application directory
sudo mkdir -p /opt/emailengine
cd /opt/emailengine

# Copy files
# - docker-compose.yml
# - .env.production
# - setup-production.sh

# Generate credentials
./setup-production.sh
```

### Step 2: Configure Reverse Proxy (Required)

Never expose EmailEngine directly to the internet. Use a reverse proxy with TLS.

#### Option A: Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name emailengine.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Long timeouts for email operations
        proxy_connect_timeout 600;
        proxy_read_timeout 600;
    }

    # WebSocket support
    location /socket.io/ {
        proxy_pass http://127.0.0.1:3000/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

server {
    listen 80;
    server_name emailengine.example.com;
    return 301 https://$server_name$request_uri;
}
```

#### Option B: Caddy (Simpler)

```caddyfile
emailengine.example.com {
    reverse_proxy localhost:3000
    header Strict-Transport-Security "max-age=31536000"
    header X-Frame-Options "SAMEORIGIN"
    header X-Content-Type-Options "nosniff"
}
```

### Step 3: Firewall Configuration

```bash
# Only allow necessary ports
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP (redirect)
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable

# Verify internal services aren't exposed
sudo netstat -tuln | grep -E '3000|2525|9993'  # Should show 127.0.0.1 only
```

### Step 4: Start Services

```bash
docker-compose up -d
docker-compose ps  # Verify all services are healthy
```

## Operations & Maintenance

### Monitoring

#### Health Checks

```bash
# Application health
curl http://localhost:3000/health

# Redis connectivity
docker-compose exec redis redis-cli -a "$REDIS_PASSWORD" ping

# Monitor resource usage (important: no limits are set)
docker stats --no-stream

# Continuous monitoring
docker stats

# Recent errors
docker-compose logs --tail=100 emailengine | grep ERROR
```

#### Key Metrics to Monitor

-   CPU usage < 80%
-   Memory usage < 90%
-   Redis memory usage < max configured
-   API response times
-   Queue lengths

### Backup Strategy

#### Automated Backup Script

```bash
#!/bin/bash
# /opt/emailengine/backup.sh

BACKUP_DIR="/backup/emailengine"
DATE=$(date +%Y%m%d-%H%M%S)

# Load environment
source /opt/emailengine/.env

# Trigger Redis save
docker-compose exec -T redis redis-cli -a "$REDIS_PASSWORD" BGSAVE
sleep 5

# Backup data
docker run --rm \
  -v emailengine_redis-data:/data \
  -v $BACKUP_DIR:/backup \
  alpine tar czf /backup/redis-$DATE.tar.gz -C /data .

# Backup config
tar czf $BACKUP_DIR/config-$DATE.tar.gz .env docker-compose.yml

# Keep 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

Add to crontab:

```bash
0 2 * * * /opt/emailengine/backup.sh
```

### Updates

#### Zero-Downtime Update

```bash
# Pull latest version
docker-compose pull

# Rolling restart
docker-compose up -d --no-deps emailengine

# Verify
docker-compose logs --tail=50 emailengine
```

#### Rollback if Needed

```bash
# Specify previous version in .env
EMAILENGINE_VERSION=2.40.0
docker-compose up -d --no-deps emailengine
```

### Performance Tuning

**Important**: EmailEngine is resource-intensive and will use available system resources.

#### System Requirements by Deployment Size

| Deployment Size | Accounts | Min RAM | Recommended RAM | CPU Cores | Workers |
| --------------- | -------- | ------- | --------------- | --------- | ------- |
| Small           | < 100    | 8GB     | 16GB            | 4         | 4       |
| Medium          | 100-500  | 16GB    | 32GB            | 8         | 8       |
| Large           | 500-2000 | 32GB    | 64GB            | 16        | 16      |
| Enterprise      | 2000+    | 64GB    | 128GB+          | 24+       | 24      |

#### Configuration Guidelines

```bash
# Adjust in .env based on your needs:

# Number of worker processes (4-24)
EENGINE_WORKERS=8

# Redis configuration
# Redis is used as a DATABASE, not a cache:
# - No memory limit is set (uses available system memory)
# - Eviction policy is 'noeviction' to prevent data loss
# - Monitor usage: docker-compose exec redis redis-cli INFO memory
```

#### Performance Notes

-   EmailEngine will automatically use available CPU and RAM
-   No artificial limits are imposed by default
-   **Redis operates as a database** with no memory limits and no eviction
-   Workers should match CPU cores (minimum 4, maximum 24)

#### Monitoring Recommendations

Since resource limits are not enforced:

1. **Critical**: Monitor Redis memory usage regularly
    ```bash
    docker-compose exec redis redis-cli INFO memory
    ```
2. Use system monitoring tools (htop, top, docker stats)
3. Set up alerts for high memory usage (especially important for Redis)
4. Ensure sufficient swap space as a safety measure
5. Consider using monitoring solutions like Prometheus + Grafana

## Troubleshooting

### Common Issues

#### Services Won't Start

```bash
# Check configuration
docker-compose config

# Verify .env file
grep -E "EENGINE_SECRET|REDIS_PASSWORD" .env

# Check ports
netstat -tuln | grep -E '3000|2525|9993'
```

#### High Memory Usage

```bash
# Check actual memory usage (no container limits set)
docker stats --no-stream

# Check Redis memory (critical - Redis has no memory limit)
docker-compose exec redis redis-cli -a "$REDIS_PASSWORD" INFO memory

# Redis memory metrics to monitor:
# - used_memory_human: Total memory used by Redis
# - used_memory_rss_human: Memory used from OS perspective
# - mem_fragmentation_ratio: Should be close to 1.0

# If memory usage is too high, you may need to:
# 1. Add more RAM to the system
# 2. Scale horizontally (multiple EmailEngine instances)
# 3. Review and optimize EmailEngine configuration
```

#### Connection Issues

```bash
# Test Redis connection
docker-compose exec emailengine redis-cli -h redis -a "$REDIS_PASSWORD" ping

# Check logs
docker-compose logs --tail=100 redis
docker-compose logs --tail=100 emailengine
```

#### Performance Issues

```bash
# Enable debug logging temporarily
docker-compose exec emailengine sh -c 'export EENGINE_LOG_LEVEL=debug'
docker-compose restart emailengine

# Check slow operations
docker-compose exec redis redis-cli -a "$REDIS_PASSWORD" SLOWLOG GET 10
```

### Recovery Procedures

#### Restore from Backup

```bash
# Stop services
docker-compose down

# Restore data
docker run --rm \
  -v emailengine_redis-data:/data \
  -v /backup:/backup \
  alpine tar xzf /backup/redis-latest.tar.gz -C /data

# Start services
docker-compose up -d
```

## Security Checklist

### Before Production

-   [ ] Strong EENGINE_SECRET (32+ characters)
-   [ ] Strong REDIS_PASSWORD (32+ characters)
-   [ ] Services bound to localhost only
-   [ ] Reverse proxy with TLS configured
-   [ ] Firewall enabled (ports 80/443 only)
-   [ ] Backup automation configured
-   [ ] **Memory monitoring in place** (critical - Redis has no limits)
-   [ ] Log rotation enabled
-   [ ] Sufficient system RAM for Redis growth
-   [ ] Swap space configured as safety measure

### Ongoing Security

-   Rotate API keys quarterly
-   Update Docker images monthly
-   Review access logs weekly
-   Test backup restoration monthly
-   Security scan quarterly

## Quick Reference

### Essential Commands

```bash
# Status
docker-compose ps
docker-compose logs --tail=50

# Restart
docker-compose restart emailengine

# Stop/Start
docker-compose stop
docker-compose start

# Full restart
docker-compose down
docker-compose up -d

# Update
docker-compose pull
docker-compose up -d

# Backup
docker-compose exec redis redis-cli -a "$REDIS_PASSWORD" BGSAVE
```

### File Locations

-   Configuration: `/opt/emailengine/.env`
-   Compose file: `/opt/emailengine/docker-compose.yml`
-   Redis data: Docker volume `emailengine_redis-data`
-   Logs: `docker-compose logs`

### Environment Switching

```bash
# To development
cp .env.development .env
docker-compose restart

# To production
cp .env.production .env
# Edit .env with secure values
docker-compose restart
```

## Support

-   Documentation: https://emailengine.app/
-   API Reference: https://api.emailengine.app/
-   Issues: https://github.com/postalsys/emailengine/issues
