# PKI Management System

Web-based PKI management for root, intermediate, and end-entity certificates (server, client, email, OCSP responder) with policy enforcement, RBAC, CRL generation, audit logging, and multi-organization isolation.

## Overview

This application provides a complete, self-hosted certificate authority (CA) management platform for organizations managing their own PKI infrastructure. It enables teams to create, issue, renew, and revoke X.509 certificates across multiple organizations with role-based access control, encrypted storage, and cryptographic audit trails.

### Key Capabilities

- **Certificate Lifecycle Management** — Create root CAs, intermediate CAs, and end-entity certificates (TLS servers, client auth, S/MIME, OCSP responders) with configurable validity periods and cryptographic algorithms.
- **Multi-Organization Isolation** — Manage separate certificate hierarchies for different organizations in a single deployment with complete data isolation.
- **Role-Based Access Control** — Three roles (admin, manager, user) with granular permissions for creation, renewal, revocation, and downloads.
- **Certificate Revocation Lists** — Automatic CRL generation and distribution when certificates are revoked; public endpoints for external validators.
- **Encrypted Storage** — Certificate private keys and sensitive data encrypted at rest; decryption only on demand.
- **Audit Logging** — Track all certificate operations (creation, renewal, revocation) with user attribution and timestamps.
- **Policy-Driven Defaults** — Enforce certificate constraints (validity periods, key algorithms, SAN validation) via centralized policy configuration.

### Use Cases

- **Internal TLS Infrastructure** — Issue and manage TLS certificates for internal services, microservices, and APIs without external CA dependencies.
- **Client Certificate Authentication** — Deploy mTLS for secure service-to-service communication or employee device authentication.
- **Email & Document Signing** — Issue S/MIME certificates for encrypted email and digitally-signed document workflows.
- **IoT & Embedded Systems** — Manage device certificates for IoT deployments with automated renewal and revocation.
- **Compliance & Regulated Environments** — Maintain full audit trails and control over certificate issuance for regulatory requirements (HIPAA, PCI-DSS, SOC 2).
- **Development & Testing** — Create test certificates on-demand for development environments without managing external CA integrations.

## Quickstart with Docker Image

You can run the application directly from the published container image without building it locally.

```bash
mkdir my-pki
cd my-pki
nano docker-compose.yml
# copy/past the one in /docker + adapt at will
nano .env
# copy/past .env.example
# or run `python utils/generate_env.py` to create `.env` with generated secret values
# and edit the rest
docker compose up -d
```

The default Compose image is `ghcr.io/entr0-pi/pki-certificates:latest`. See [docker/README.md](docker/README.md) for Docker-specific setup details.

## How-to for local dev

### Prerequisites

- Python 3.11+
- Node.js 18+ and `npm` for rebuilding frontend CSS

### 1. Install dependencies

```bash
pip install -r requirements.txt
npm install
```

### 2. Configure environment

Create a local `.env` file. The application auto-loads it at startup.

Required secrets:

- `PKI_ENCRYPTION_KEY`
- `PKI_ENCRYPTION_SALT`
- `PKI_API_KEY_ADMIN`
- `PKI_API_KEY_MANAGER`
- `PKI_API_KEY_USER`
- `PKI_JWT_SECRET`

Commonly used settings:

| Variable | Default | Notes |
|----------|---------|-------|
| `PKI_HOST` | `0.0.0.0` | Bind address |
| `PKI_PORT` | `8000` | FastAPI port |
| `PKI_BASE_URL` | `http://localhost:8000` | Used in generated CRL distribution URLs |
| `PKI_DB_AUTO_REINIT` | `false` | Rebuild invalid DB from schema and keep a `*.invalid.bak` backup |
| `PKI_DATA_DIR` | `<repo>/data` | Must be an absolute path if set |
| `PKI_DB_PATH` | `<repo>/database/pki.db` | Must be an absolute path if set |
| `PKI_SESSION_MINUTES` | `15` | Session lifetime |
| `PKI_AUTH_COOKIE_NAME` | `pki_session` | Session cookie name |
| `PKI_COOKIE_SECURE` | `true` | Runtime default in code; must stay `true` behind HTTPS |
| `PKI_COOKIE_SAMESITE` | `lax` | Cookie SameSite policy |
| `PKI_COOKIE_DOMAIN` | empty | Optional cookie domain scope |

Example `.env`:

```dotenv
PKI_HOST=127.0.0.1
PKI_PORT=8000
PKI_BASE_URL=http://localhost:8000
PKI_DB_AUTO_REINIT=false

PKI_DATA_DIR=
PKI_DB_PATH=

PKI_ENCRYPTION_KEY=replace-with-a-strong-random-value
PKI_ENCRYPTION_SALT=replace-with-a-random-base64-salt

PKI_API_KEY_ADMIN=replace-with-admin-api-key
PKI_API_KEY_MANAGER=replace-with-manager-api-key
PKI_API_KEY_USER=replace-with-user-api-key
PKI_JWT_SECRET=replace-with-a-long-random-jwt-secret
PKI_SESSION_MINUTES=60

PKI_AUTH_COOKIE_NAME=pki_session
PKI_COOKIE_SECURE=true
PKI_COOKIE_SAMESITE=lax
PKI_COOKIE_DOMAIN=
```

Notes:

- Leave `PKI_DATA_DIR` and `PKI_DB_PATH` empty to use the repo defaults.
- If you set either path, it must be absolute.
- The application accepts your auth and cookie settings as provided; deployment hardening remains the operator's responsibility.
- Use a strong `PKI_JWT_SECRET` and keep it at 32+ random characters even though the current code only requires it to be non-empty.
- Do not tighten cookie or CSP settings in production without validating the affected login, form, download, and frontend flows in your environment.
- Use `PKI_COOKIE_SECURE=true` in HTTPS deployments.

### 3. Initialize the database

```bash
python scripts/init_db.py
```

### 4. Build frontend assets

```bash
npm run build:css
```

This compiles `frontend/static/src/input.css` into `frontend/static/vendor/bundle.css`.

### 5. Run the application

```bash
python backend/app.py
```

Open `http://localhost:8000` and sign in with one of the configured API keys.

## Frontend build workflow

The frontend is server-rendered with Jinja templates and a compiled Tailwind CSS bundle.

- `npm install` installs Tailwind CSS and DaisyUI locally
- `npm run build:css` rebuilds the production CSS bundle
- `npm run watch:css` watches templates and regenerates CSS during UI work

If you only run the app and do not change templates or frontend dependencies, the committed CSS bundle is sufficient.

## Project structure

```text
backend/
  app.py                    FastAPI entrypoint and route handlers
  auth.py                   Session auth and RBAC helpers
  db.py                     Database access layer
  path_config.py            Path resolution for data/db locations
  cert_crypto.py            Shared certificate utilities
  revoke_cert_crypto.py     Revocation and CRL generation
  root_ca_create_crypto.py
  intermediate_ca_create_crypto.py
  end_entity_create_crypto.py
  config/
    policy.json             Certificate policy and defaults
    rbac.json               Route-to-role authorization map
  openssl/
    config.txt              OpenSSL config assets (for reference only, not used)

frontend/
  templates/                Jinja HTML templates
  static/
    src/input.css           Tailwind source file
    vendor/bundle.css       Built CSS served by FastAPI
    *.js                    Small UI behaviors

database/
  pki_schema.sql            SQLite schema
  pki.db                    Runtime database file

docs/
  *.md                      Operational, security, API, and frontend docs

tests/
  conftest.py
  requirements-dev.txt      Test-only Python dependencies
  test_*.py                 Backend and UI workflow coverage

scripts/
  init_db.py                Database initialization helper

utils/
  generate_env.py           Creates `.env` from `.env.example` and generates secret values

package.json                npm scripts for frontend asset builds
tailwind.config.js          Tailwind/DaisyUI configuration
requirements.txt            Python runtime dependencies
```

## Technical Documentation

| Document | Purpose |
|----------|---------|
| [docs/ROUTES.md](docs/ROUTES.md) | HTTP routes, auth requirements, and RBAC matrix |
| [docs/DB_SCHEMA.md](docs/DB_SCHEMA.md) | SQLite schema and table relationships |
| [docs/SECURITY.md](docs/SECURITY.md) | Deployment hardening, secret handling, and operational security notes |
| [docs/FRONTEND.md](docs/FRONTEND.md) | Tailwind/DaisyUI frontend build workflow and asset pipeline |
| [docs/CRON_JOBS.md](docs/CRON_JOBS.md) | Scheduling guidance for consistency checks and maintenance tasks |
| [docs/TEST_PLAN.md](docs/TEST_PLAN.md) | Test scope and verification strategy |
| [docs/SKELETON.md](docs/SKELETON.md) | Project skeleton/reference layout |

## Testing

```bash
pytest -v
```

Install optional test dependencies from `tests/requirements-dev.txt` if your environment does not already have them.

## Security

- Keep `.env`, API keys, JWT secrets, and encryption material out of version control.
- Use HTTPS in production and set `PKI_COOKIE_SECURE=true`.
- Back up both the database and encrypted certificate storage.
- Review [docs/SECURITY.md](docs/SECURITY.md) before deploying outside local development.

Last update: 2026 03 10 — Encryption upgraded to AES-256-GCM
