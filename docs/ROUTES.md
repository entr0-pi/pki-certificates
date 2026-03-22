# Routes and JWT Access Reference

This document lists all HTTP routes currently defined in `backend/app.py`, including payload shapes and role-based access control via JWT.

## Authentication and JWT Model

Session JWTs carry a `role` claim. Three roles exist:

| Role | Description |
|------|-------------|
| `admin` | Full access to all routes and operations |
| `manager` | Can create and manage end-entity certificates only |
| `user` | Read-only: view and download certificates and CRLs |

### JWT Payload (example)

```json
{
  "sub": "user",
  "role": "admin",
  "iat": 1740000000,
  "exp": 1740000900,
  "iss": "pki-webapp"
}
```

### Login Keys by Role

The `.env` file must define one API key per role:

```env
PKI_API_KEY_ADMIN=...
PKI_API_KEY_MANAGER=...
PKI_API_KEY_USER=...
```

`POST /auth/session` matches `api_key` against these values and issues a session cookie JWT with the matching role.

Operator note:
- `PKI_JWT_SECRET` should be provisioned as a strong random secret of at least 32 characters.
- `PKI_COOKIE_SECURE` and `PKI_COOKIE_SAMESITE` are deployment choices; changing them can affect login and form workflows.

## Access Control Configuration (`backend/config/rbac.json`)

Route permissions are **fully configuration-driven** through `backend/config/rbac.json`. This is the **single source of truth** for all application routes—public and protected. No Python code changes are needed to adjust access policies.

### Configuration Format

Each route is defined as `"METHOD /path/template": [roles]`:

- **Public routes** use the `["public"]` sentinel: `"GET /auth/login": ["public"]`
- **Protected routes** list allowed roles: `"GET /toolbox": ["admin"]`
- **Routes with no explicit role list** allow any authenticated user (access granted after session validation)
- **Path templates** support FastAPI syntax: `{param}` → parameter matching, `/*` → prefix matching

### Route Access Rules

1. **Unauthenticated requests** to public routes → allowed
2. **Unauthenticated requests** to protected routes → redirect to `/auth/login` (HTML) or 401 (API)
3. **Authenticated requests** without role restriction → allowed
4. **Authenticated requests** with role restriction → check user's role against allowed list; deny with 403 if insufficient

### Example Configuration

```json
{
  "_comment": "Per-route role access control...",
  "GET /": ["admin", "manager", "user"],
  "GET /auth/login": ["public"],
  "POST /auth/session": ["public"],
  "GET /static/*": ["public"],
  "GET /toolbox": ["admin"],
  "POST /create-organization": ["admin"],
  "GET /health": ["admin", "manager"],
  "GET /organizations": ["admin", "manager", "user"]
}
```

### Modifying Route Access

To change route permissions **without touching Python code**:

1. Edit `backend/config/rbac.json`
2. Restart the server (configuration is validated and cached at startup)
3. Invalid RBAC config will fail startup with a detailed error message

This approach ensures operators can adjust fine-grained role-based access control without requiring code reviews or deployments.

### Startup Validation

The application validates `rbac.json` at startup:

1. **Format validation** — each entry is `"METHOD /path"` with non-empty roles list
2. **Role validation** — all roles are in the known set (`admin`, `manager`, `user`, or `public`)
3. **Public route coverage** — all expected public routes (login, health, CRL, static) are marked `["public"]`
4. **Private route coverage** — all expected protected routes are in the config and NOT marked `["public"]`

If any validation fails, startup aborts with a clear error message. Examples:

- Missing public route: `Public routes missing from rbac.json: GET /healthz`
- Missing private route: `Private route GET /toolbox missing from rbac.json`
- Misconfigured route: `Private route GET /toolbox must not be marked as ["public"]`

## Auth and Error Behavior

- All business routes require a valid session JWT cookie.
- Unauthenticated HTML routes redirect to `/auth/login`.
- Unauthenticated API/file routes return `401`.
- For insufficient permissions:
  - HTML/form/view requests return `403.html`.
  - API/file requests return JSON `{"detail": "Insufficient permissions"}` with HTTP `403`.
- Most create/update routes accept HTML form payloads (`application/x-www-form-urlencoded` or `multipart/form-data`), not JSON.
- JSON snippets below are JSON-equivalent field maps for documentation.

## Role Matrix by Route Group

> **📋 Source of Truth**: The tables below are generated from `backend/config/rbac.json`. For authoritative role-based access control rules, **always refer directly to `backend/config/rbac.json`**. These tables are for reference only—the canonical access rules are in the configuration file.

Legend: `✓` allowed, `-` denied, `public` no auth required.

### Authentication Routes

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `GET /auth/login` | public | public | public | Login page |
| `POST /auth/session` | public | public | public | Creates session cookie |
| `POST /auth/logout` | public | public | public | Clears session cookie |

### UI Pages

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `GET /` | ✓ | ✓ | ✓ | Landing page |
| `GET /toolbox` | ✓ | - | - | Utility tools |
| `GET /organizations/{org_id}/manage` | ✓ | ✓ | ✓ | Organization dashboard |
| `GET /organizations/{org_id}/certificates/{cert_id}/popup` | ✓ | ✓ | ✓ | Certificate details popup |
| `GET /organizations/{org_id}/certificates/{cert_id}/renew` | ✓ | ✓ | - | Renewal form |
| `GET /organizations/{org_id}/root-ca` | ✓ | - | - | Root CA form |
| `GET /organizations/{org_id}/intermediate-ca` | ✓ | - | - | Intermediate CA form |
| `GET /organizations/{org_id}/end-entity` | ✓ | ✓ | - | End-entity form |

### Organization Management

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `POST /create-organization` | ✓ | - | - | Creates organization |
| `GET /organizations` | ✓ | ✓ | ✓ | Lists organizations |

### Certificate Creation

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `POST /organizations/{org_id}/root-ca` | ✓ | - | - | Create root CA |
| `POST /organizations/{org_id}/intermediate-ca` | ✓ | - | - | Create intermediate CA |
| `POST /organizations/{org_id}/end-entity` | ✓ | ✓ | - | Create end-entity certificate |

### Certificate Actions

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `POST /organizations/{org_id}/certificates/{cert_id}/revoke` | ✓ | - | - | Revoke certificate |
| `GET /organizations/{org_id}/certificates/{cert_id}/download` | ✓ | ✓ | - | Download cert (`pem`,`p12`,`chain`) |
| `GET /organizations/{org_id}/certificates/{cert_id}/p12-password` | ✓ | ✓ | - | Retrieve PKCS#12 export password |
| `GET /organizations/{org_id}/certificates/{cert_id}/private-key/plain` | ✓ | - | - | Download private key |

### CRL Routes

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `GET /organizations/{org_id}/crl/{issuer_name}` | public | public | public | Issuer CRL (public endpoint) |
| `GET /organizations/{org_id}/crl/download` | public | public | public | Latest CRL (public endpoint) |
| `GET /organizations/{org_id}/crl/bundle` | public | public | public | Bundle of all available organization CRLs (public endpoint) |

### Health, Diagnostics, and Backup

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `GET /healthz` | public | public | public | Liveness probe |
| `GET /health` | ✓ | ✓ | - | DB/system health |
| `GET /api/check-consistency` | ✓ | ✓ | - | DB vs disk consistency check |
| `GET /api/organizations/{org_id}/crls` | ✓ | ✓ | ✓ | List available CRLs per issuer |
| `GET /admin/backup/database` | ✓ | - | - | Download full backup ZIP |
| `POST /admin/restore/database` | ✓ | - | - | Upload and restore full backup ZIP |

## Detailed Route Reference

### `GET /auth/login`
- Auth required: no
- Request JSON: none
- Response JSON: none (HTML login page)

### `POST /auth/session`
- Auth required: no
- Content-Type: form
- Request (JSON-equivalent):
```json
{
  "api_key": "your-api-key"
}
```
- Response JSON: none (redirect + session cookie on success, HTML error on failure)

### `POST /auth/logout`
- Auth required: no
- Request JSON: none
- Response JSON: none (clears session cookie + redirect)

### `GET /`
- Auth required: yes
- Request JSON: none
- Response JSON: none (HTML landing page)

### `GET /toolbox`
- Auth required: yes
- Request JSON: none
- Response JSON: none (HTML toolbox page)

### `GET /organizations/{org_id}/manage`
- Auth required: yes
- Request JSON: none
- Response JSON: none (HTML organization dashboard)

### `GET /organizations/{org_id}/certificates/{cert_id}/popup`
- Auth required: yes
- Request JSON: none
- Response JSON: none (HTML certificate details popup page)

### `GET /organizations/{org_id}/certificates/{cert_id}/renew`
- Auth required: yes
- Request JSON: none
- Response JSON: none (HTML renewal form page)

### `GET /organizations/{org_id}/root-ca`
- Auth required: yes
- Request JSON: none
- Response JSON: none (HTML root CA form page)

### `GET /organizations/{org_id}/intermediate-ca`
- Auth required: yes
- Request JSON: none
- Response JSON: none (HTML intermediate CA form page)

### `GET /organizations/{org_id}/end-entity`
- Auth required: yes
- Request JSON: none
- Response JSON: none (HTML end-entity form page)

### `POST /create-organization`
- Auth required: yes
- Content-Type: form
- Request (JSON-equivalent):
```json
{
  "org_display_name": "Acme Corporation"
}
```
- Response JSON: none (HTML success/error page)

### `GET /organizations`
- Auth required: yes
- Request JSON: none
- Response (example):
```json
{
  "count": 1,
  "organizations": [
    {
      "id": 1,
      "name": "Acme Corporation",
      "org_dir": "D:/pki/data/org_1_acme_corporation"
    }
  ]
}
```
- Error shape (example):
```json
{
  "error": "message",
  "organizations": []
}
```

### `POST /organizations/{org_id}/root-ca`
- Auth required: yes
- Content-Type: form
- Request (JSON-equivalent):
```json
{
  "cert_name": "ROOT_CA",
  "C": "CA",
  "ST": "QUEBEC",
  "L": "MONTREAL",
  "O": "CERTIFICATE-AUTHORITY",
  "OU": "PUBLIC",
  "CN": "ROOT_CA",
  "email": "",
  "subjectAltName": "",
  "enddate": "2099-12-31",
  "eccurve": "secp384r1",
  "renewal_of_cert_id": "",
  "root_ca_password": "user-provided-password-to-protect-root-ca"
}
```
- **Security note - Two-Factor Root CA Protection**:
  - `root_ca_password` is required and user-provided (e.g., "MySecurePassword123")
  - System also generates a random filesystem password stored in `.pwd.enc`
  - Root CA private key is encrypted with: `HMAC-SHA256(key=filesystem_password, msg=root_ca_password)`
  - **The user password is NEVER stored to disk and NEVER logged** — it exists only in-memory during private key encryption
  - User must provide the same password later when:
    - Creating an Intermediate CA (to unlock root CA for signing)
    - Revoking certificates issued by the root CA (to unlock root CA for CRL regeneration)
  - See [SECURITY.md - Root CA Private Key Access Control](#root-ca-private-key-access-control-two-factor) for full details
- Response JSON: none (HTML page with result)
- HTTP 422: if `root_ca_password` is empty or missing

### `POST /organizations/{org_id}/intermediate-ca`
- Auth required: yes
- Content-Type: form
- Request (JSON-equivalent):
```json
{
  "cert_name": "TLS",
  "C": "CA",
  "ST": "QUEBEC",
  "L": "MONTREAL",
  "O": "CERTIFICATE-AUTHORITY",
  "OU": "PUBLIC",
  "CN": "TLS",
  "email": "",
  "subjectAltName": "",
  "enddate": "2035-12-31",
  "eccurve": "secp384r1",
  "renewal_of_cert_id": "",
  "root_user_password": "password-to-unlock-root-ca-private-key"
}
```
- **Security note**: `root_user_password` is required and must match the password used when the Root CA was created. The password is never stored or logged; it is used only to derive the effective unlock passphrase for the Root CA private key via HMAC-SHA256. See [SECURITY.md - Root CA Private Key Access Control](#root-ca-private-key-access-control) for details.
- Response JSON: none (HTML page with result)
- HTTP 422: if `root_user_password` is empty or missing
- HTTP 500: if `root_user_password` is incorrect (invalid key decryption)

### `POST /organizations/{org_id}/end-entity`
- Auth required: yes
- Content-Type: form
- Request (JSON-equivalent):
```json
{
  "cert_name": "api-server-01",
  "cert_type": "server",
  "issuer_name": "TLS",
  "issuer_type": "intermediate",
  "C": "CA",
  "ST": "QUEBEC",
  "L": "MONTREAL",
  "O": "CERTIFICATE-AUTHORITY",
  "OU": "PUBLIC",
  "CN": "api.example.local",
  "email": "",
  "subjectAltName": "DNS:api.example.local,IP:10.0.0.10",
  "enddate": "2028-12-31",
  "eccurve": "secp384r1",
  "renewal_of_cert_id": ""
}
```
- Response JSON: none (HTML page with result)

### `POST /organizations/{org_id}/certificates/{cert_id}/revoke`
- Auth required: yes
- Content-Type: form
- Request (JSON-equivalent):
```json
{
  "reason": "keyCompromise",
  "root_user_password": "password-to-unlock-root-ca-private-key"
}
```
- **Security note**: If the certificate was issued by the Root CA, `root_user_password` is required and must be correct. The password is used to regenerate the CRL after revocation. For certificates issued by an Intermediate CA, the `root_user_password` field is not required.
- Valid revocation reasons: `unspecified`, `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`
- Response JSON: none (HTML dashboard/error page)
- HTTP 422: if `root_user_password` is empty and certificate is issued by Root CA
- HTTP 500: if `root_user_password` is incorrect (invalid CRL generation)

### `GET /organizations/{org_id}/certificates/{cert_id}/download`
- Auth required: yes
- Request JSON: none
- Query params:
```json
{
  "format": "pem"
}
```
- Allowed `format`: `pem`, `p12`, `chain`, `full_chain`
- Response JSON: none (file download)
- Filename formats:
  - PEM: `Org-{org_id}_{cert_name}.pem`
  - PKCS#12: `Org-{org_id}_{cert_name}.p12`
  - Chain: `Org-{org_id}_{cert_name}_chain.pem`
  - Full chain (with root): `Org-{org_id}_{cert_name}_chain.pem`

### `GET /organizations/{org_id}/certificates/{cert_id}/p12-password`
- Auth required: yes
- Request JSON: none
- Response (example):
```json
{
  "password": "generated-export-password"
}
```

### `GET /organizations/{org_id}/certificates/{cert_id}/private-key/plain`
- Auth required: yes
- Request JSON: none
- Response JSON: none (private key file download)
- Filename format: `Org-{org_id}_{cert_name}.key.pem`
- Restrictions: Server certificates only

### `GET /organizations/{org_id}/crl/{issuer_name}`
- Auth required: no (public CRL endpoint for certificate validators)
- Request JSON: none
- Query params (optional):
```json
{
  "issuer_cert_id": 12,
  "format": "pem"
}
```
- Allowed `format`: `pem` (default), `der`
- Response JSON: none (CRL file download in requested format)
- Filename formats:
  - PEM: `Org-{org_id}_{issuer_name}_crl.pem`
  - DER: `Org-{org_id}_{issuer_name}_crl.der`
- Notes: Returns the CRL for a specific issuer in the requested format. Default is PEM; use `?format=der` for DER-encoded binary CRL. This endpoint is typically embedded in certificate CDP (CRL Distribution Point) extensions and accessed by certificate validators and OpenSSL's `crl_download` feature.

### `GET /organizations/{org_id}/crl/download`
- Auth required: no (public CRL endpoint for certificate validators)
- Request JSON: none
- Query params (optional):
```json
{
  "format": "pem"
}
```
- Allowed `format`: `pem` (default), `der`
- Response JSON: none (CRL file download in requested format)
- Filename formats:
  - PEM: `Org-{org_id}_{issuer_name}_crl.pem`
  - DER: `Org-{org_id}_{issuer_name}_crl.der`
- Notes: Returns the preferred organization CRL (intermediate first, then root) in the requested format. Default is PEM; use `?format=der` for DER-encoded binary CRL. Useful for applications that need a single CRL endpoint without knowing the issuer name.

### `GET /organizations/{org_id}/crl/bundle`
- Auth required: no (public CRL bundle endpoint for certificate validators)
- Request JSON: none
- Query params (optional):
```json
{
  "format": "pem"
}
```
- Allowed `format`: `pem` (default), `der`
- Response JSON: none (CRL bundle in requested format)
- Filename formats:
  - PEM: `Org-{org_id}_{issuer_name}_crl-bundle.pem` (uses primary issuer name)
  - DER: `Org-{org_id}_{issuer_name}_crl-bundle.der` (uses primary issuer name)
- Notes: Returns a bundle containing all available organization CRLs (intermediates first, then roots) in the requested format.
  - **PEM format** (default): Multiple PEM blocks separated by newlines, suitable for `openssl verify -CRLfile` and most PKI clients.
  - **DER format** (`?format=der`): ASN.1 SEQUENCE of DER-encoded CRLs. Use this for structured binary bundling. OpenSSL's `crl` command expects a single CRL, not a SEQUENCE; use `asn1parse -in file.der -inform DER` to inspect the structure.

### `GET /healthz`
- Auth required: no
- Request JSON: none
- Response (example):
```json
{
  "status": "ok"
}
```

### `GET /health`
- Auth required: yes
- Request JSON: none
- Response (example):
```json
{
  "status": "healthy",
  "database": {
    "status": "healthy",
    "path": "D:/pki/database/pki.db"
  }
}
```

### `GET /api/check-consistency`
- Auth required: yes
- Request JSON: none
- Response (success example):
```json
{
  "success": true,
  "stats": {
    "organizations_checked": 1,
    "certificates_checked": 12
  },
  "issues": [],
  "issue_count": 0
}
```
- Response (error example):
```json
{
  "success": false,
  "error": "message",
  "stats": {},
  "issues": [
    {
      "level": "error",
      "message": "Check failed: message"
    }
  ]
}
```

### `GET /api/organizations/{org_id}/crls`
- Auth required: yes
- Request JSON: none
- Response (example):
```json
[
  {
    "issuer_name": "root-ca",
    "cert_type": "root",
    "has_crl": true,
    "download_url": "/organizations/1/crl/root-ca",
    "revoked_count": 0,
    "last_updated": "2026-03-08T14:30:45.123456"
  },
  {
    "issuer_name": "intermediate-ca",
    "cert_type": "intermediate",
    "has_crl": true,
    "download_url": "/organizations/1/crl/intermediate-ca",
    "revoked_count": 3,
    "last_updated": "2026-03-08T10:15:22.654321"
  }
]
```
- Response (empty example):
```json
[]
```
- Notes: Returns list of all CA issuers (root and intermediate) with CRL availability status, download URLs, revocation counts, and last update timestamps. Used by org dashboard to dynamically populate CRL distribution section with operational insights.

### `GET /admin/backup/database`
- Auth required: yes (admin only)
- Request JSON: none
- Response: ZIP file attachment containing:
  - `pki.db` — consistent SQLite database snapshot at root level
  - `data/` — entire encrypted certificate storage directory tree
- Filename format: `pki-backup-YYYY-MM-DD.zip`
- Content-Type: `application/zip`
- Notes:
  - Uses SQLite online backup API (`connection.backup()`) for WAL-safe consistent snapshots
  - Safe to run while the application is live — does not lock the database
  - Database backup created in a temp file, added to ZIP, then automatically cleaned up
  - All encrypted certificate files (`*.pem.enc`, `*.p12.enc`) preserved in their original structure
  - Backup operation is logged with the requesting user's name
  - Access restricted to admin role only via RBAC
- HTTP 403: if user lacks admin role
- HTTP 500: if backup creation fails (DB or archive error)

### `POST /admin/restore/database`
- Auth required: yes (admin only)
- Content-Type: `multipart/form-data`
- Request (form):
  - `backup_file` (required) — ZIP file previously exported via `GET /admin/backup/database`
- Response: HTML redirect to `/toolbox?restore=ok` (success) or `/toolbox?restore=error&detail=...` (failure)
- Upload limits:
  - Maximum upload size: **5 GB**
  - Maximum uncompressed size: **10 GB**
  - Maximum ZIP entries: **50,000**
- Validation checks:
  - ZIP file integrity (BadZipFile rejection)
  - Path traversal protection (rejects entries starting with `/` or containing `..`)
  - Content validation (only `pki.db` and `data/` allowed at root)
  - SQLite database integrity (`PRAGMA integrity_check`)
  - Schema version match (must equal current `SCHEMA_VERSION`)
- Restore process:
  1. **Receive upload** — Stream file in 1 MB chunks; abort if size exceeded
  2. **Validate ZIP** — Check structure, paths, uncompressed size; reject invalid entries
  3. **Validate database** — Extract `pki.db`, verify integrity and schema version
  4. **Extract data** — Extract `data/` contents to staging directory
  5. **Atomic DB swap** — Close connections, swap database file, reopen
  6. **Atomic data swap** — Clear current data directory, copy new files (handles mounted volumes)
  7. **Cleanup** — Remove backup files and temporary directories
  8. **Redirect** — Return to toolbox with success/error message
- Error recovery:
  - Before point of no return: all uploads are rejected without touching live data
  - After DB swap: old database preserved as `.restore_old` backup
  - After data swap failure: restore from backup copy; DB already swapped (consistent)
  - If data swap fails mid-operation: staging directory cleaned up on next attempt
- Security notes:
  - **Atomic operations**: Database and data directory swapped atomically to maintain consistency
  - **Cross-device safe**: Uses `shutil.move()` for compatibility with Docker volume mounts
  - **Destructive operation**: Replaces all live data without undo (backups preserved during recovery)
  - **Safe for live apps**: Operates on consistent snapshots; no application restart required
  - Restore operation is logged with the requesting user's name
  - Access restricted to admin role only via RBAC
- HTTP 303: See Other redirect (success or error)
- HTTP 403: if user lacks admin role
- HTTP 422: if form validation fails

## Security Notes

- API keys should be distinct per role.
- JWT role claims are signed using `PKI_JWT_SECRET`.
- The application currently accepts any non-empty `PKI_JWT_SECRET`; operators should use a strong 32+ character random secret.
- `PKI_SESSION_MINUTES` timeout applies equally to all roles.
- Expired JWTs are rejected before role checks.
- `manager` cannot create/renew root or intermediate certificates because the corresponding `POST` routes are admin-only.
