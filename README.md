# PKI Management System

Web-based PKI management for root, intermediate, and end-entity certificates (server, client, email, OCSP responder) with policy enforcement, RBAC, CRL generation, audit logging, and multi-organization isolation.

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/ROUTES.md](docs/ROUTES.md) | HTTP routes, auth requirements, and RBAC matrix |
| [docs/DB_SCHEMA.md](docs/DB_SCHEMA.md) | SQLite schema and table relationships |
| [docs/SECURITY.md](docs/SECURITY.md) | Deployment hardening, secret handling, and operational security notes |
| [docs/FRONTEND.md](docs/FRONTEND.md) | Tailwind/DaisyUI frontend build workflow and asset pipeline |
| [docs/CRON_JOBS.md](docs/CRON_JOBS.md) | Scheduling guidance for consistency checks and maintenance tasks |
| [docs/TEST_PLAN.md](docs/TEST_PLAN.md) | Test scope and verification strategy |
| [docs/SKELETON.md](docs/SKELETON.md) | Project skeleton/reference layout |

## Quickstart

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
| `PKI_COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
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
PKI_COOKIE_SECURE=false
PKI_COOKIE_SAMESITE=lax
PKI_COOKIE_DOMAIN=
```

Notes:

- Leave `PKI_DATA_DIR` and `PKI_DB_PATH` empty to use the repo defaults.
- If you set either path, it must be absolute.
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

## Frontend workflow

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
    config.txt              OpenSSL config assets

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

package.json                npm scripts for frontend asset builds
tailwind.config.js          Tailwind/DaisyUI configuration
requirements.txt            Python runtime dependencies
```

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
