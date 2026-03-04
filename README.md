# 🔐 PKI Management System

A **modern, web-based Public Key Infrastructure (PKI) management platform** with intuitive UI, policy-driven security controls, and role-based access management.

> **Streamline certificate lifecycle management** — Create, renew, and revoke certificates for root, intermediate, and end-entity CAs through a clean web interface. All with built-in multi-organization isolation, policy enforcement, and compliance-ready audit trails.

---

## ✨ Key Strengths

- **🎨 Intuitive Web UI** — No command-line cryptography; manage certificates visually
- **🔒 Policy-Driven Security** — Define certificate rules once in `policy.json`; enforcement is automatic
- **👥 Role-Based Access Control (RBAC)** — Admin, manager, user roles with granular route permissions
- **🏢 Multi-Org Isolation** — Separate certificate namespaces; zero data leakage between organizations
- **📋 Certificate Chains** — Full root → intermediate → end-entity lifecycle support
- **♻️ Revocation & CRL** — Automatic CRL generation on revocation with versioning
- **✅ Audit Trail** — All operations logged with user identity and timestamp
- **🧪 High Test Coverage** — 40+ automated tests covering cert generation, RBAC, CRL, consistency
- **⚙️ Configurable Everything** — Host, port, database path, storage location, session TTL — all via environment variables
- **🌍 Cross-Platform** — Windows, Linux, macOS; Docker support included

---

## 🚀 Quickstart

### Local (Recommended for First-Time Users)

**Prerequisites:** Python 3.11+

```bash
# 1. Clone and install
git clone <repo>
cd pki
pip install -r requirements.txt

# 2. Set environment variables (create .env file or export)
export PKI_API_KEY_ADMIN="admin-secret-key-123"
export PKI_API_KEY_MANAGER="manager-secret-key-456"
export PKI_API_KEY_USER="user-secret-key-789"
export PKI_JWT_SECRET="your-jwt-secret-min-32-chars"

# 3. Initialize database
python scripts/init_db.py

# 4. Start the app
python backend/app.py
```

**Open browser:** `http://localhost:8000`
**Login:** Use one of your API keys (admin recommended for first run)

### Docker

```bash
# Build image
docker build -t pki:latest .

# Run container
docker run -d \
  --name pki-app \
  -p 8000:8000 \
  -e PKI_API_KEY_ADMIN="admin-secret-key-123" \
  -e PKI_API_KEY_MANAGER="manager-secret-key-456" \
  -e PKI_API_KEY_USER="user-secret-key-789" \
  -e PKI_JWT_SECRET="your-jwt-secret-min-32-chars" \
  -v pki-data:/app/data \
  -v pki-db:/app/database \
  pki:latest
```

**Open browser:** `http://localhost:8000`

---

## 📖 Documentation

| Document | Purpose |
|----------|---------|
| [**ROUTES.md**](docs/ROUTES.md) | Complete API endpoint reference + role-based access control matrix |
| [**DB_SCHEMA.md**](docs/DB_SCHEMA.md) | Database schema, tables, relationships |
| [**SECURITY.md**](docs/SECURITY.md) | Security considerations and hardening |
| [**CRON_JOBS.md**](docs/CRON_JOBS.md) | Scheduling consistency checks |

---

## 🎯 Main Features

### 1️⃣ Certificate Issuance
Create **Root CA**, **Intermediate CA**, and **End-Entity** (server, client, email) certificates through the web UI.
- Policy-driven subject field locking and enforcement
- Configurable validity periods
- Multiple EC curves and key sizes
- Subject Alternative Names (SAN) for server certificates

### 2️⃣ Policy-Driven Configuration
All cryptographic behavior controlled via `backend/config/policy.json` — no code changes needed:
- Certificate lifetimes (root: 7300 days, intermediate: 3650 days, end-entity: 825 days)
- Allowed EC curves (P-256, P-384, etc.)
- Subject field locking rules
- FIPS compliance flags

### 3️⃣ Role-Based Access Control (RBAC)
Three built-in roles with configurable permissions:

| Role | Typical Use | Permissions |
|------|------------|-------------|
| **admin** | Operator/DevOps | Full access — create root/intermediate, revoke, manage orgs |
| **manager** | Team lead | Create end-entity certs, renew, download certs |
| **user** | Auditor/viewer | Read-only — view certs, download, run consistency checks |

Permissions are **configuration-driven** in `backend/config/rbac.json`; change routes without restarting the backend.

### 4️⃣ Certificate Renewal
Renew expired/expiring certificates with automatic revocation of the previous cert (marked `superseded`).
- Pre-filled form with original certificate details
- Update validity period or certificate name
- CRL automatically updated with previous cert

### 5️⃣ Revocation & CRL
- Revoke active certificates with reason code (keyCompromise, superseded, etc.)
- Automatic CRL generation and version tracking
- Download latest or full CRL bundle per organization
- Issuer-specific CRL endpoints

### 6️⃣ Multi-Organization Support
Each organization gets isolated certificate namespace:
- Separate data directories: `data/org_<id>_<name>/`
- Separate database records (org isolation enforced at query level)
- Audit trail includes organization context

### 7️⃣ Consistency Checking
Built-in validation to detect mismatches between database and filesystem:
- Certificate file existence
- Extension metadata consistency
- Chain integrity (issuer_cert_id links)
- CRL consistency
- Serial number uniqueness

Run manually or schedule via cron/Windows Task Scheduler.

### 8️⃣ Audit Trail
All certificate operations logged:
- User identity (from JWT)
- Operation type (created, revoked, renewed)
- Timestamp
- Details (cert type, reason, etc.)

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `PKI_HOST` | `0.0.0.0` | Bind address (use `127.0.0.1` for localhost only) |
| `PKI_PORT` | `8000` | Server port |
| `PKI_BASE_URL` | `http://localhost:8000` | Public URL (used in CRL distribution points) |
| `PKI_DATA_DIR` | `<repo>/data` | Org/cert artifact storage (absolute path) |
| `PKI_DB_PATH` | `<repo>/database/pki.db` | SQLite database file (absolute path) |
| `PKI_API_KEY_ADMIN` | _(required)_ | API key for admin role |
| `PKI_API_KEY_MANAGER` | _(required)_ | API key for manager role |
| `PKI_API_KEY_USER` | _(required)_ | API key for user role |
| `PKI_JWT_SECRET` | _(required)_ | JWT signing secret (min 32 chars) |
| `PKI_SESSION_MINUTES` | `15` | Session timeout in minutes |
| `PKI_COOKIE_SECURE` | `false` | Set `true` for HTTPS environments |

**Example `.env` file:**

```bash
PKI_HOST=0.0.0.0
PKI_PORT=8000
PKI_BASE_URL=https://pki.example.com
PKI_DATA_DIR=/var/lib/pki/data
PKI_DB_PATH=/var/lib/pki/database/pki.db
PKI_API_KEY_ADMIN=your-admin-key-here
PKI_API_KEY_MANAGER=your-manager-key-here
PKI_API_KEY_USER=your-user-key-here
PKI_JWT_SECRET=your-jwt-secret-min-32-chars
PKI_SESSION_MINUTES=30
PKI_COOKIE_SECURE=true
```

Load with: `source .env` (Linux/macOS) or create `.env` and the app will auto-load it.

---

## 📂 Project Structure

```
backend/              # FastAPI app + crypto logic
├── app.py            # Main web application
├── db.py             # SQLAlchemy Core database layer
├── helpers.py        # Utility functions
├── *_create_crypto.py # Certificate generation scripts (root, intermediate, end-entity)
├── revoke_cert_crypto.py # CRL/revocation logic
├── config/           # Configuration files
│   ├── policy.json   # Certificate policy & defaults
│   └── rbac.json     # Role-based access control matrix

frontend/             # Web UI
├── templates/        # Jinja2 HTML templates
├── static/           # CSS, JS, images

database/             # Database
├── pki_schema.sql    # SQLite schema
└── pki.db            # SQLite database (created at runtime)

data/                 # PKI artifacts (created at runtime)
├── org_1_example/
│   ├── 1_root/
│   ├── 2_intermediates/
│   └── 3_end-entities/

tests/                # Test suite
├── test_certificate_generation.py
├── test_policy_enforcement.py
├── test_database_consistency.py
├── test_rbac.py
└── test_revocation_crl.py

scripts/              # Utility scripts
├── init_db.py        # Initialize/reset database
├── check_consistency.py # Consistency validation
└── start_webapp.sh   # Startup helper
```

---

## 🧪 Testing

Run the full test suite:

```bash
pytest -v
```

Run specific test categories:

```bash
pytest -v -m unit         # Fast policy logic tests
pytest -v -m openssl      # Cryptography/PEM parsing tests
pytest -v -m integration  # HTTP + database tests
```

**Test coverage:** 40+ tests across certificate generation, RBAC, CRL, database consistency, and policy enforcement. **All green** = zero regressions.

---

## 🔄 Certificate Workflow

1. **Login** → Submit API key at `/auth/login`
2. **Create Org** → Initialization of certificate namespace
3. **Create Root CA** → Foundation of the PKI hierarchy
4. **Create Intermediate CA** → Issued by root
5. **Create End-Entity Certs** → Issued by intermediate (server, client, email types)
6. **Renew** → (Optional) Extend validity or update details
7. **Revoke** → Mark as superseded/compromised; update CRL
8. **Download** → PEM, PKCS12, chain, private key
9. **CRL Distribution** → Share CRL via web endpoint or file download

---

## 🚨 Security Considerations

- **HTTPS recommended** for production — set `PKI_COOKIE_SECURE=true` and `PKI_BASE_URL=https://...`
- **API keys must be strong** — generate with `openssl rand -base64 32`
- **JWT secret must be strong** — min 32 chars; rotate periodically
- **Database backups** — SQLite file should be backed up regularly
- **Audit logs** — review periodically for anomalies
- **Organization isolation** — enforced at database query level; verify with consistency checks

See [**SECURITY.md**](docs/SECURITY.md) for detailed hardening recommendations.

---

## 📋 Changelog

**Latest Release: v1.0.0**

- ✅ Multi-organization support with isolation
- ✅ Policy-driven configuration system
- ✅ Role-based access control (RBAC) with configurable permissions
- ✅ Certificate renewal with auto-revocation
- ✅ CRL generation and versioning
- ✅ Audit trail for all operations
- ✅ Consistency checking (filesystem ↔ database)
- ✅ Docker support
- ✅ 40+ automated tests (zero regressions)
- ✅ Web UI with DaisyUI theming

---

## 📞 Support & Contributing

- **Issues/Bugs:** Open an issue on GitHub
- **Documentation:** See [docs/](docs/) directory
- **Testing:** Run `pytest -v` before submitting PRs

---

## 🎯 Next Steps

1. **Deploy locally** → See Quickstart above
2. **Review RBAC config** → Edit `backend/config/rbac.json` for your org's roles
3. **Customize policy** → Edit `backend/config/policy.json` for certificate defaults
4. **Run tests** → Verify everything works: `pytest -v`
5. **Schedule consistency checks** → See [CRON_JOBS.md](docs/CRON_JOBS.md)
6. **Review audit logs** → Monitor `/organizations/{org_id}/audit` endpoint (if exposed)

---

**Built with FastAPI + SQLAlchemy + Cryptography + DaisyUI** ✨
