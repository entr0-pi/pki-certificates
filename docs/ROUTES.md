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

## Access Control Configuration (`backend/config/rbac.json`)

Route permissions are configuration-driven through `backend/config/rbac.json`.

- Routes listed in `rbac.json` are restricted to the listed roles.
- Routes not listed are allowed to any authenticated role (default-allow).
- Invalid RBAC config fails application startup.
- Permission changes require editing `rbac.json` and restarting the server.

Example:

```json
{
  "GET /toolbox": ["admin"],
  "POST /create-organization": ["admin"],
  "GET /health": ["admin", "manager"]
}
```

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

> **⚠️ Source of Truth**: The tables below reflect the current `backend/rbac.json` configuration. For authoritative role-based access control rules, always refer to `backend/rbac.json` directly. These tables may become outdated if `rbac.json` is modified without regenerating this documentation.

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
| `GET /organizations/{org_id}/certificates/{cert_id}/download` | ✓ | ✓ | ✓ | Download cert (`pem`,`p12`,`chain`) |
| `GET /organizations/{org_id}/certificates/{cert_id}/private-key/plain` | ✓ | - | - | Download private key |

### CRL Routes

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `GET /organizations/{org_id}/crl/{issuer_name}` | public | public | public | Issuer CRL (public endpoint) |
| `GET /organizations/{org_id}/crl/download` | public | public | public | Latest CRL (public endpoint) |
| `GET /organizations/{org_id}/crl/bundle` | public | public | public | CRL bundle (public endpoint) |
| `GET /organizations/{org_id}/crl/{issuer_name}/bundle` | public | public | public | Issuer CRL bundle (public endpoint) |

### Health and Diagnostics

| Route | admin | manager | user | Notes |
|------|:-----:|:-------:|:----:|------|
| `GET /health` | ✓ | ✓ | - | DB/system health |
| `GET /api/check-consistency` | ✓ | ✓ | ✓ | DB vs disk consistency check |

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
  "renewal_of_cert_id": ""
}
```
- Response JSON: none (HTML page with result)

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
  "renewal_of_cert_id": ""
}
```
- Response JSON: none (HTML page with result)

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
  "reason": "keyCompromise"
}
```
- Response JSON: none (HTML dashboard/error page)

### `GET /organizations/{org_id}/certificates/{cert_id}/download`
- Auth required: yes
- Request JSON: none
- Query params:
```json
{
  "format": "pem"
}
```
- Allowed `format`: `pem`, `p12`, `chain`
- Response JSON: none (file download)

### `GET /organizations/{org_id}/certificates/{cert_id}/private-key/plain`
- Auth required: yes
- Request JSON: none
- Response JSON: none (private key file download)

### `GET /organizations/{org_id}/crl/{issuer_name}`
- Auth required: no (public CRL endpoint for certificate validators)
- Request JSON: none
- Query params (optional):
```json
{
  "issuer_cert_id": 12
}
```
- Response JSON: none (CRL file download)

### `GET /organizations/{org_id}/crl/download`
- Auth required: no (public CRL endpoint for certificate validators)
- Request JSON: none
- Response JSON: none (CRL file download)

### `GET /organizations/{org_id}/crl/bundle`
- Auth required: no (public CRL endpoint for certificate validators)
- Request JSON: none
- Response JSON: none (CRL bundle file download)

### `GET /organizations/{org_id}/crl/{issuer_name}/bundle`
- Auth required: no (public CRL endpoint for certificate validators)
- Request JSON: none
- Query params (optional):
```json
{
  "issuer_cert_id": 12
}
```
- Response JSON: none (CRL bundle file download)

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

## Security Notes

- API keys should be distinct per role.
- JWT role claims are signed using `PKI_JWT_SECRET`.
- `PKI_SESSION_MINUTES` timeout applies equally to all roles.
- Expired JWTs are rejected before role checks.
- `manager` cannot create/renew root or intermediate certificates because the corresponding `POST` routes are admin-only.
