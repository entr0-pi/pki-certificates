# Docker Deployment

This directory contains Docker artifacts for deploying the PKI Management System in containerized environments.

## Files

- **Dockerfile** — Multi-stage build for production-ready container image
- **docker-compose.yml** — Orchestration for local development and testing
- **.env.example** — Template for environment configuration (committed to git)
- **.env** — Your local secrets file (created by copying .env.example, excluded from git)

## Quick Start

### 1. Prepare Environment

```bash
cd docker/

# Copy the template to create your local .env file
# (.env is excluded from git and should contain your actual secrets)
cp .env.example .env

# Edit .env with your specific values using a text editor:
nano .env  # or your preferred editor

# Required changes:
# - PKI_ENCRYPTION_KEY: strong password for at-rest encryption (generate: openssl rand -base64 32)
# - PKI_ENCRYPTION_SALT: random base64-encoded 32-byte salt (generate: openssl rand -base64 32)
# - PKI_API_KEY_ADMIN: strong random value (32+ chars)
# - PKI_API_KEY_MANAGER: strong random value (32+ chars)
# - PKI_API_KEY_USER: strong random value (32+ chars)
# - PKI_JWT_SECRET: strong random JWT signing secret (32+ chars)
```

### 2. Run Locally with Docker Compose

```bash
# From the docker/ directory:
docker-compose up

# App is now accessible at http://localhost:8000
```

### 3. Test Health Endpoint

```bash
# Should return {"status": "ok"} without authentication
curl http://localhost:8000/healthz

# Health check with database status (requires auth)
curl -b "pki_session=<your-jwt-cookie>" http://localhost:8000/health
```

## Building the Image

```bash
# From the project root:
docker build -f docker/Dockerfile -t pki-app:latest .
```

## Architecture

### Single-Instance Constraint

The PKI app uses **SQLite + local encrypted filesystem** and **must run as a single container instance**. This is the correct architecture for internal PKI management.

- **Persistent volumes required:**
  - `/app/data` — Encrypted certificate artifacts
  - `/app/database` — SQLite database file

### Container Security

- Runs as non-root user `pki` (UID 1000)
- Health checks on unauthenticated `/healthz` endpoint
- Secrets loaded from environment variables
- All certificate artifacts encrypted at rest

## Cloud Deployment

Suitable platforms for single-instance with persistent volumes:

- **Fly.io** — Persistent volumes via `fly volumes`
- **Render** — Persistent disk service
- **Railway.app** — Persistent volumes
- **GCP Cloud Run** — With Cloud Filestore or Persistent Disk
- **AWS ECS** — Single task with EFS volume
- **Self-hosted** — Any VPS with Docker (DigitalOcean, Hetzner, Linode)

### Example: Fly.io Deployment

```bash
# 1. Create app
fly launch

# 2. Create persistent volumes
fly volumes create pki_data --size 10
fly volumes create pki_database --size 5

# 3. Copy .env values to fly secrets
fly secrets set PKI_ENCRYPTION_KEY="your-key" \
  PKI_ENCRYPTION_SALT="your-salt" \
  PKI_API_KEY_ADMIN="your-admin-key" \
  ...

# 4. Deploy
fly deploy
```

## Environment Variables

See [.env](.env) for complete documentation of all configuration options:

- **Encryption**: `PKI_ENCRYPTION_KEY`, `PKI_ENCRYPTION_SALT`
- **Authentication**: `PKI_API_KEY_ADMIN`, `PKI_API_KEY_MANAGER`, `PKI_API_KEY_USER`, `PKI_JWT_SECRET`
- **Server**: `PKI_HOST`, `PKI_PORT`, `PKI_BASE_URL`
- **Logging**: `PKI_LOG_LEVEL` (DEBUG, INFO, WARNING, ERROR)
- **Timeouts**: `PKI_SUBPROCESS_TIMEOUT_SECONDS`

## Verification Checklist

- [ ] `docker build -t pki-app .` completes without errors
- [ ] `docker-compose up` starts app without errors
- [ ] `curl http://localhost:8000/healthz` returns `{"status":"ok"}`
- [ ] App is accessible at http://localhost:8000
- [ ] Can create organizations and certificates via web UI
- [ ] Volume data persists after container restart
- [ ] Logs are visible in `docker-compose logs`

## Troubleshooting

### "Connection refused" at /healthz

Ensure the container is fully started (check logs with `docker-compose logs`)

### Encryption errors

- Verify `ENCRYPTION_KEY` is set and consistent
- Verify `PKI_ENCRYPTION_SALT` is a valid base64-encoded 32-byte value
- If migrating data: ensure same salt as source installation

### Database errors

- Check volume is mounted correctly: `docker volume inspect docker_pki_database`
- Verify permissions: `docker exec pki-app ls -la /app/database`
- If corrupted: delete the volume and reinitialize: `docker volume rm docker_pki_database`

### Permission denied

Ensure `pki` user (UID 1000) has write access to volumes
