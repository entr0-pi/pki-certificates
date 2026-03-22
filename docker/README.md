# Docker Deployment

This directory contains Docker artifacts for deploying the PKI Management System in containerized environments.

If you are starting from the repository root, the main [README.md](../README.md) points here for Docker-specific deployment guidance.

## Files

- **Dockerfile** — Multi-stage build for production-ready container image
- **docker-compose.yml** — Orchestration for local development and testing
- **.env** — Your local Docker secrets file (created by copying ../.env.example, excluded from git)

See [../.env.example](../.env.example) for complete environment variable documentation and defaults.

## Quick Start

### 1. Prepare Environment

You can prepare `docker/.env` in either of these ways:

- manually copy `../.env.example` and edit it
- use the helper in `../utils` to generate secrets and write the file for you

Recommended helper flow:

```bash
# From the project root:
python utils/generate_env.py --env dev --output docker/.env

# Review the generated file and adjust Docker-specific values if needed
```

See [../utils/README.md](../utils/README.md) for the generator behavior, profiles, and flags.

```bash
cd docker/

# Copy the root .env.example to create your local .env file
# (.env is excluded from git and should contain your actual secrets)
cp ../.env.example .env

# Edit .env with your specific values using a text editor:
nano .env  # or your preferred editor

# Required changes (see ../.env.example for full documentation):
# - PKI_ENCRYPTION_KEY: strong password for at-rest encryption
#   Generate: openssl rand -base64 32
# - PKI_ENCRYPTION_SALT: random base64-encoded 32-byte salt
#   Generate: openssl rand -base64 32
# - PKI_API_KEY_ADMIN, PKI_API_KEY_MANAGER, PKI_API_KEY_USER: strong random values (32+ chars)
#   Generate: python -c "import secrets; print(secrets.token_urlsafe(32))"
# - PKI_JWT_SECRET: strong random JWT signing secret (32+ chars)
#   Generate: python -c "import secrets; print(secrets.token_urlsafe(32))"

# Note: docker-compose.yml hardcodes certain Docker-specific values:
# - PKI_HOST=0.0.0.0 (required for container networking)
# - PKI_PORT=8000 (matches exposed port)
# - PKI_DATA_DIR=/app/data and PKI_DB_PATH=/app/database/pki.db (managed by volumes)
# - PKI_COOKIE_SECURE=false (for local development; set to true in production)
```

If you use `utils/generate_env.py`, the generated file still needs a final review before deployment, especially for:

- `PKI_BASE_URL`
- `PKI_COOKIE_SECURE`
- notification settings
- any production-specific host or proxy assumptions

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

## Environment Variables

See [../.env.example](../.env.example) for complete documentation of all configuration options.
You can also generate `docker/.env` with [../utils/generate_env.py](../utils/generate_env.py); see [../utils/README.md](../utils/README.md).

**Docker-specific settings** (hardcoded in docker-compose.yml, do not edit in .env):
- `PKI_HOST=0.0.0.0` — Required for container networking
- `PKI_PORT=8000` — Must match exposed port
- `PKI_DATA_DIR=/app/data` — Managed by Docker volume `pki_data`
- `PKI_DB_PATH=/app/database/pki.db` — Managed by Docker volume `pki_database`
- `PKI_LOG_LEVEL=INFO` — Logging level (override in .env if needed)
- `PKI_COOKIE_SECURE=false` — For local dev (set to true in production)

**Secrets to configure in docker/.env** (required):
- `PKI_ENCRYPTION_KEY` — At-rest encryption password
- `PKI_ENCRYPTION_SALT` — PBKDF2 salt
- `PKI_API_KEY_ADMIN`, `PKI_API_KEY_MANAGER`, `PKI_API_KEY_USER` — Role-based API keys
- `PKI_JWT_SECRET` — JWT signing secret

### Environment Variable Resolution Order

Docker-compose loads variables in this precedence (highest to lowest):

| Priority | Source | Used For |
|----------|--------|----------|
| 1 (Highest) | `environment:` in docker-compose.yml | Docker-specific hardcoded values (PKI_HOST, PKI_PORT, PKI_DATA_DIR, PKI_DB_PATH, PKI_COOKIE_SECURE, PKI_BASE_URL) |
| 2 | `env_file: - .env` in docker-compose.yml | Secrets and deployment config (loaded from docker/.env) |
| 3 | `docker/.env` file | Local development defaults and secrets (copied from ../‌.env.example) |
| 4 (Lowest) | `ENV` in Dockerfile | Image-level fallback defaults (used only if running `docker run` without docker-compose.yml) |

**In practice:**
- docker-compose.yml values **override** docker/.env values
- docker/.env provides fallback for any variables not set in docker-compose.yml
- Dockerfile ENV only applies if container runs without docker-compose.yml

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
