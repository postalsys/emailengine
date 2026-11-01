# EmailEngine Docker Deployment Guide

This guide covers everything from local development to production deployment of EmailEngine using Docker.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Production Deployment](#production-deployment)
- [Operations & Maintenance](#operations--maintenance)
- [Running several instances](#running-several-instances)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites

- Docker Engine 20.10.0+ and Docker Compose 2.0.0+
- **System Requirements**:
    - Development: 4GB RAM minimum
    - Production: 8GB RAM minimum, 16GB+ recommended
- **Critical Notes**:
    - No Docker resource limits are imposed
    - Redis has NO memory limit and uses 'noeviction' policy (database mode)
    - **MUST monitor memory usage** to prevent system OOM
- **Monitoring**: Use `docker stats` and Redis INFO memory regularly

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

- No authentication required
- Services accessible from any network
- Debug logging enabled
- Minimal resource requirements

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

- Redis authentication required
- Services bound to localhost only
- Optimized logging and persistence
- Health checks and resource limits

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

The image starts EmailEngine with `EENGINE_API_PROXY=true`, so the client address is read from the `X-Forwarded-For` header. Set `EENGINE_API_PROXY_ADDRESSES` in `.env` to the address of your proxy (IPs or CIDRs, comma-separated; for a proxy on the Docker host this is usually the bridge gateway, e.g. `172.17.0.1`, or the proxy container's address). Without it the header is trusted from any peer, EmailEngine logs a warning on every start, and the admin IP allowlist and per-token address restrictions cannot be relied on.

#### Option A: Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name emailengine.example.com;

    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # EmailEngine sends its own security headers (Content-Security-Policy, X-Frame-Options,
    # X-Content-Type-Options, Referrer-Policy, Permissions-Policy), and Strict-Transport-Security
    # once the service URL setting is https. Do not add them here as well: a second copy of a
    # header is at best redundant and, for Content-Security-Policy, the two are both enforced.

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

    # No extra location is needed for the live updates. EmailEngine streams account state changes as
    # Server-Sent Events over the ordinary path (/v1/changes and the admin UI's own stream) and sends
    # `X-Accel-Buffering: no` with them, which nginx honours, so the events are not held in a buffer.
    # The read timeout above does apply to them: an idle feed is cut after 600s. A browser EventSource
    # reconnects on its own; a /v1/changes consumer written by hand has to do the same.
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
}
```

EmailEngine sets the security headers itself (see the note in the Nginx example), so the Caddyfile needs no `header` lines.

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

- CPU usage < 80%
- Memory usage < 90%
- Redis memory usage < max configured
- API response times
- Queue lengths

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

#### Update

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
# Specify previous version in .env. The published image tags carry the `v` prefix the git tags
# carry (v2.82.0, v2.82, v2, latest), so a bare 2.40.0 resolves to no image at all.
EMAILENGINE_VERSION=v2.40.0
docker-compose up -d --no-deps emailengine
```

### Performance Tuning

**Important**: EmailEngine is resource-intensive and will use available system resources.

#### System Requirements by Deployment Size

| Accounts | Min RAM | Recommended RAM | CPU Cores | Workers |
| -------- | ------- | --------------- | --------- | ------- |
| < 100    | 8GB     | 16GB            | 4         | 4       |
| 100-500  | 16GB    | 32GB            | 8         | 8       |
| 500-2000 | 32GB    | 64GB            | 16        | 16      |
| 2000+    | 64GB    | 128GB+          | 24+       | 24      |

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

- EmailEngine will automatically use available CPU and RAM
- No artificial limits are imposed by default
- **Redis operates as a database** with no memory limits and no eviction
- Workers should match CPU cores (minimum 4, maximum 24)

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

## Running several instances

Several EmailEngine instances can share one Redis database, for example as the replicas of a Kubernetes Deployment behind a Service. Each email account is served by exactly one instance at a time, and any instance answers API requests for any account.

### How it works

- **Ownership.** Every instance keeps a heartbeat record in Redis and claims a share of the accounts, spread evenly across the instances that are running. An account is served by the instance recorded as its owner, which keeps one connection to the mail server for it, exactly as a single instance does.
- **Requests for other accounts.** An API request that reaches an instance which does not serve the account is passed to the instance that does, over the cluster port, and the answer comes back unchanged, downloads included. The SMTP server, the IMAP proxy, outgoing mail and exports work the same way.
- **Failover.** When an instance stops gracefully, it hands its accounts over before it exits, and the others take them within a second or two. When an instance crashes or is cut off, the others take its accounts once its heartbeat expires (`EENGINE_CLUSTER_HEARTBEAT_TTL`, 20 seconds by default); until then, API requests for those accounts answer `503 WorkerNotAvailable`, which a client should retry as it already has to for a single instance that restarts. Mail that arrives meanwhile is not lost: the new owner finds it when it connects. A shorter TTL shortens the window, at the price of an instance whose process stalls for longer than the TTL briefly giving its accounts up. An instance that was frozen or cut off for longer than the TTL checks which of its accounts were taken over before it announces anything for them, so no webhook is sent twice.
- **Scaling.** A new instance takes its share from the others, about 1/N of the accounts, which are handed over without a gap: the old owner closes the connection before the new one opens it, and a request that arrives in between waits for the new owner. Accounts move in batches of 100 about a second apart, so a large fleet settles in minutes. When the whole fleet starts at once, an account is left for the instance it belongs to while that instance is still starting (for up to two heartbeat TTLs), so the first instance to be ready does not take every account only to hand most of them on.
- **Outgoing mail.** A queued message is sent under a lock, so a retry never runs next to a send that is still in progress, and a retry after the message was sent does not send it again.
- **Settings and live updates.** Settings changes, certificate renewals, listener restarts and the live change feed reach every instance through Redis.

### Requirements

- Every instance uses the same Redis database and the same `EENGINE_SECRET`. Do not run a version without multi-instance support next to one with it: the older one does not know about account ownership and connects every account itself. Moving from such a version therefore needs `strategy: { type: Recreate }` on the Deployment for that one upgrade (the default RollingUpdate always runs old and new pods side by side); later upgrades can roll. During a rolling upgrade an instance of a newer release keeps the accounts it holds. A request that needs an instance of the other release answers `400 UnsupportedCommand` when the older instance does not know the command, or `503 WorkerNotAvailable` when the releases speak a different cluster protocol, until the older pod is gone.
- Every instance sets `EENGINE_CLUSTER_PORT` and can reach the others on it. The port carries account data, message contents included, in plain HTTP. Every call is signed with a key the instances share through Redis, so nobody without that key can make an instance do anything, but the answers are neither signed nor encrypted. Keep the port on the private network between the instances and do not publish it; where that network is not trusted, put mutual TLS in front of it, for example with a service mesh.
- The address an instance announces is its first external IPv4 address by default, which is the pod IP in Kubernetes. Set `EENGINE_CLUSTER_ADDRESS` when that address is not reachable from the other instances. Every instance calls itself at that address when it starts and logs `The advertised cluster address does not lead back to this instance` when it gets no answer; a NetworkPolicy has to allow the cluster port between the pods as well.
- Leave `EENGINE_INSTANCE_ID` unset unless you need stable names. The default, the host name plus a random suffix, makes every start a new member. A process that starts with the id of a member whose heartbeat has not expired yet, such as a container restarted in place with a fixed id, waits for it to expire before it serves anything.
- Export files are written to the disk of the instance that runs the export, and a download through another instance fetches the file from it. Mount a shared volume at `EENGINE_EXPORT_PATH` if finished exports have to survive the instance that wrote them.
- Plan Redis for more connections: every worker thread of every instance holds its own.

### Kubernetes example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
    name: emailengine
spec:
    replicas: 3
    selector:
        matchLabels:
            app: emailengine
    template:
        metadata:
            labels:
                app: emailengine
        spec:
            # Above the preStop sleep plus the time a graceful stop takes (at most about 10 seconds),
            # so accounts are handed over rather than waiting for the heartbeat to expire
            terminationGracePeriodSeconds: 30
            containers:
                - name: emailengine
                  image: postalsys/emailengine:v2
                  env:
                      - name: EENGINE_REDIS
                        valueFrom:
                            secretKeyRef: { name: emailengine, key: redis-url }
                      - name: EENGINE_SECRET
                        valueFrom:
                            secretKeyRef: { name: emailengine, key: secret }
                      - name: EENGINE_CLUSTER_PORT
                        value: '3001'
                  ports:
                      - containerPort: 3000
                        name: api
                      - containerPort: 3001
                        name: cluster
                  readinessProbe:
                      httpGet: { path: /health/ready, port: api }
                      periodSeconds: 5
                  livenessProbe:
                      httpGet: { path: /health/live, port: api }
                      periodSeconds: 10
                  lifecycle:
                      # Gives the Service time to stop sending requests before the process is told to stop
                      preStop:
                          exec: { command: ['sleep', '5'] }
---
apiVersion: v1
kind: Service
metadata:
    name: emailengine
spec:
    selector:
        app: emailengine
    ports:
        # Only the API: the cluster port is for the instances themselves
        - name: api
          port: 3000
          targetPort: api
```

The readiness check stays negative until an instance has settled which accounts it serves, so a new pod gets traffic only once it can answer. A HorizontalPodAutoscaler can scale the Deployment on CPU. Every scale step moves about 1/N of the accounts, so scale in steps of one and leave a few minutes between them.

### Monitoring

- `GET /v1/stats` counts the accounts of every instance and lists the instances, and the Workers page of the admin UI shows them when there are several.
- Each instance exports `cluster_members`, `cluster_owned_accounts`, `cluster_forwarded_calls` (by command and outcome) and `cluster_forward_duration_seconds` on `/metrics`.
- A log line `Lost cluster membership` means an instance missed its heartbeat for longer than the TTL: a stalled process, or Redis unreachable from it.
- `cluster_forwarded_calls` with the outcome `error` or `unreachable` growing for one owner means the other instances cannot reach it on the cluster port. That instance keeps its accounts, since it still holds its heartbeat, and requests for them that land elsewhere fail until the network is fixed.

### Limits

- **Redis failover.** Ownership lives in Redis. A failover to a replica that had not received the latest writes (Sentinel, or any asynchronous replica) can bring back an older owner record, and an account handed over just before can be synced by two instances until the next full ownership pass, about 30 seconds at the default TTL. Webhooks for new messages stay exactly once (they are announced from a queue in Redis), but a flag change or a deletion in that window can be announced twice or not at all.
- **A stalled main thread.** An instance whose main thread stalls for longer than the TTL while its worker threads keep running stops announcing until it has rejoined, and drops what it held back for accounts taken over meanwhile. New messages are announced by the new owner. A flag change or deletion the stalled instance had already written to its index is not announced by either. A frozen process (all threads), a crash and a Redis outage are not affected.
- **Redis Cluster** is not supported: every instance uses one Redis database, standalone or behind Sentinel.

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
# Enable debug logging. The level is read from the environment at startup, so it has to be set on
# the container rather than exported inside it - `exec ... export` sets it in a shell that then
# exits, and `restart` reuses the container's existing environment either way.
echo 'EENGINE_LOG_LEVEL=debug' >> .env
docker-compose up -d --no-deps --force-recreate emailengine

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

- [ ] Strong EENGINE_SECRET (32+ characters)
- [ ] Strong REDIS_PASSWORD (32+ characters)
- [ ] Services bound to localhost only
- [ ] Reverse proxy with TLS configured
- [ ] Firewall enabled (ports 80/443 only)
- [ ] Backup automation configured
- [ ] **Memory monitoring in place** (critical - Redis has no limits)
- [ ] Log rotation enabled
- [ ] Sufficient system RAM for Redis growth
- [ ] Swap space configured as safety measure

### Ongoing Security

- Rotate API keys quarterly
- Update Docker images monthly
- Review access logs weekly
- Test backup restoration monthly
- Security scan quarterly

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

- Configuration: `/opt/emailengine/.env`
- Compose file: `/opt/emailengine/docker-compose.yml`
- Redis data: Docker volume `emailengine_redis-data`
- Logs: `docker-compose logs`

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

- Support: https://emailengine.app/support or support@postalsys.com
- Documentation: https://learn.emailengine.app/
- API Reference: https://learn.emailengine.app/docs/api/emailengine-api
- Bug reports: https://github.com/postalsys/emailengine/issues
