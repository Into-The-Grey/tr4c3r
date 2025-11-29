# Docker Deployment Guide

This guide covers deploying TR4C3R using Docker and Docker Compose.

## Quick Start

```bash
# Clone and enter directory
cd tr4c3r

# Start the stack
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f tr4c3r-api
```

The API will be available at `http://localhost:8000`.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network                            │
│                                                              │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐       │
│  │  TR4C3R API │   │  PostgreSQL │   │    Redis    │       │
│  │   :8000     │──▶│    :5432    │   │    :6379    │       │
│  └─────────────┘   └─────────────┘   └─────────────┘       │
│         │                                   ▲               │
│         └───────────────────────────────────┘               │
│                                                              │
│  ┌─────────────┐                                            │
│  │   Worker    │ (optional, with --profile full)           │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

## Services

| Service | Description | Port |
|---------|-------------|------|
| `tr4c3r-api` | Main API server | 8000 |
| `postgres` | PostgreSQL database | 5432 |
| `redis` | Redis cache | 6379 |
| `tr4c3r-worker` | Background job processor | - |

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required in production - CHANGE THESE!
TR4C3R_MASTER_KEY=your-secure-32-char-master-key
TR4C3R_JWT_SECRET=your-secure-jwt-secret-key
POSTGRES_PASSWORD=your-secure-postgres-password

# Optional
TR4C3R_PORT=8000
TR4C3R_LOG_LEVEL=INFO
```

### Security Checklist

Before deploying to production:

1. ☐ Change `TR4C3R_MASTER_KEY` to a secure random value
2. ☐ Change `TR4C3R_JWT_SECRET` to a secure random value
3. ☐ Change `POSTGRES_PASSWORD` to a secure password
4. ☐ Configure proper network firewall rules
5. ☐ Enable HTTPS via reverse proxy (nginx/traefik)
6. ☐ Set up proper backup procedures

Generate secure keys:

```bash
# Generate a secure random key
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Build Options

### Production Build

```bash
# Build production image
docker build --target production -t tr4c3r:latest .

# Run standalone
docker run -p 8000:8000 tr4c3r:latest
```

### Development Build

```bash
# Build development image (includes test tools)
docker build --target development -t tr4c3r:dev .

# Run tests in container
docker run tr4c3r:dev

# Run with mounted source for live reload
docker run -v $(pwd)/src:/app/src tr4c3r:dev pytest -v
```

## Docker Compose Profiles

### Basic Stack (API + Database + Cache)

```bash
docker-compose up -d
```

### Full Stack (includes Worker)

```bash
docker-compose --profile full up -d
```

## Common Operations

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f tr4c3r-api

# Last 100 lines
docker-compose logs --tail=100 tr4c3r-api
```

### Restart Services

```bash
# Restart all
docker-compose restart

# Restart specific service
docker-compose restart tr4c3r-api
```

### Stop and Remove

```bash
# Stop services
docker-compose stop

# Stop and remove containers
docker-compose down

# Remove containers and volumes (⚠️ deletes data)
docker-compose down -v
```

### Scale Workers

```bash
# Run 3 worker instances
docker-compose --profile full up -d --scale tr4c3r-worker=3
```

### Access Container Shell

```bash
# API container
docker-compose exec tr4c3r-api /bin/bash

# Database
docker-compose exec postgres psql -U tr4c3r -d tr4c3r
```

## Data Persistence

Data is stored in Docker volumes:

| Volume | Contents |
|--------|----------|
| `tr4c3r-data` | Application data |
| `tr4c3r-logs` | Log files |
| `tr4c3r-exports` | Exported reports |
| `tr4c3r-postgres-data` | Database files |
| `tr4c3r-redis-data` | Redis persistence |

### Backup Volumes

```bash
# Backup PostgreSQL
docker-compose exec postgres pg_dump -U tr4c3r tr4c3r > backup.sql

# Backup all data volumes
docker run --rm -v tr4c3r-data:/data -v $(pwd):/backup \
    alpine tar czf /backup/data-backup.tar.gz /data
```

### Restore Volumes

```bash
# Restore PostgreSQL
cat backup.sql | docker-compose exec -T postgres psql -U tr4c3r -d tr4c3r

# Restore data volume
docker run --rm -v tr4c3r-data:/data -v $(pwd):/backup \
    alpine tar xzf /backup/data-backup.tar.gz -C /
```

## Health Checks

All services have health checks configured:

```bash
# Check service health
docker-compose ps

# Manual health check
curl http://localhost:8000/health
```

## Reverse Proxy Setup

### Nginx Configuration

```nginx
upstream tr4c3r {
    server localhost:8000;
}

server {
    listen 443 ssl http2;
    server_name osint.example.com;

    ssl_certificate /etc/ssl/certs/osint.crt;
    ssl_certificate_key /etc/ssl/private/osint.key;

    location / {
        proxy_pass http://tr4c3r;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Traefik Configuration

Add labels to docker-compose.yml:

```yaml
tr4c3r-api:
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.tr4c3r.rule=Host(`osint.example.com`)"
    - "traefik.http.routers.tr4c3r.tls.certresolver=letsencrypt"
    - "traefik.http.services.tr4c3r.loadbalancer.server.port=8000"
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs tr4c3r-api

# Check if port is in use
lsof -i :8000

# Rebuild without cache
docker-compose build --no-cache
```

### Database Connection Issues

```bash
# Check if postgres is healthy
docker-compose exec postgres pg_isready -U tr4c3r

# Check network connectivity
docker-compose exec tr4c3r-api ping postgres
```

### Out of Disk Space

```bash
# Clean up unused resources
docker system prune -a

# Remove unused volumes
docker volume prune
```

### Permission Issues

```bash
# Fix volume permissions
docker-compose exec tr4c3r-api chown -R tr4c3r:tr4c3r /app/data
```

## Production Deployment Checklist

- [ ] Set all environment variables in `.env`
- [ ] Configure HTTPS reverse proxy
- [ ] Set up automated backups
- [ ] Configure log rotation
- [ ] Set up monitoring/alerting
- [ ] Review and harden firewall rules
- [ ] Test disaster recovery procedure
- [ ] Document runbooks for common operations

## Resource Requirements

### Minimum

- CPU: 1 core
- RAM: 2 GB
- Disk: 10 GB

### Recommended

- CPU: 4 cores
- RAM: 8 GB
- Disk: 50 GB SSD

## Related Documentation

- [API Documentation](API.md)
- [Authentication](AUTHENTICATION.md)
- [Data Encryption](DATA_ENCRYPTION.md)
- [Logging Infrastructure](LOGGING_INFRASTRUCTURE.md)
