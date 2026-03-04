# PKI Management System - Security Documentation

**Last Updated**: March 3, 2026
**Status**: Production-Ready ✅

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Architecture & Threat Model](#architecture--threat-model)
3. [Implemented Security Controls](#implemented-security-controls)
4. [Authentication & Authorization](#authentication--authorization)
5. [Encryption at Rest](#encryption-at-rest)
6. [API Security](#api-security)
7. [Certificate Management Security](#certificate-management-security)
8. [Audit & Logging](#audit--logging)
9. [Deployment Security](#deployment-security)
10. [Incident Response](#incident-response)

---

## Security Overview

This PKI Management System is a high-security application for certificate lifecycle management. It implements defense-in-depth security practices across all layers.

### Key Security Principles

- **Least Privilege**: Role-based access control (RBAC) with three roles: admin, manager, user
- **Defense in Depth**: Multiple security layers (authentication, CSRF, validation, logging)
- **Fail Secure**: Errors hide implementation details; detailed logs go to server only
- **Entropy**: Random salts and session IDs for cryptographic operations
- **Validation**: Input validation at system boundaries; RFC 5280 compliance for certificates
- **Audit Trail**: All operations logged with session identity and timestamps

---

## Architecture & Threat Model

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                    Browser/Client                        │
│          (HTML forms, session cookies, CSRF checks)      │
└─────────────────┬───────────────────────────────────────┘
                  │ HTTPS/TLS
┌─────────────────▼───────────────────────────────────────┐
│               FastAPI Web Server                         │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Middleware Layer                                    │ │
│  │ ├─ Authentication (JWT in cookies)                 │ │
│  │ ├─ CSRF Protection (X-Requested-With header)       │ │
│  │ ├─ Security Headers (CSP, HSTS, X-Frame-Options)   │ │
│  │ └─ Rate Limiting (planned)                         │ │
│  └─────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Application Layer                                   │ │
│  │ ├─ Role-Based Access Control (RBAC)                │ │
│  │ ├─ Input Validation (revocation reasons, etc.)     │ │
│  │ ├─ Business Logic (CA hierarchy checks)            │ │
│  │ └─ Error Handling (sanitized responses)            │ │
│  └─────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ Data Access Layer (SQLAlchemy Core)                │ │
│  │ ├─ Parameterized Queries (SQL injection prevention)│ │
│  │ ├─ Transaction Management                          │ │
│  │ └─ Constraint Enforcement (DB level)               │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────┬───────────────────────────────────────┘
                  │
        ┌─────────┴──────────┐
        ▼                    ▼
    ┌────────────┐    ┌──────────────────┐
    │  SQLite DB │    │ Encrypted Folder │
    │            │    │ Structure (Certs)│
    │ Certificate│    │ (/data/org_*)    │
    │ metadata   │    │                  │
    │ Extensions │    │ .pem.enc files   │
    │ Audit logs │    │ (AES-128-CBC)    │
    └────────────┘    └──────────────────┘
```

### Threat Model

| Threat | Actor | Impact | Mitigation |
|--------|-------|--------|-----------|
| **Session Hijacking** | Network attacker | Unauthorized operations | HTTPS-only, SameSite=strict, HTTPOnly cookies |
| **CSRF** | Web attacker | Account takeover | X-Requested-With header + SameSite cookie |
| **SQL Injection** | Authenticated user | Data breach | Parameterized queries (SQLAlchemy) |
| **Cross-org Access** | Authenticated user | Revoke wrong certs | Organization ownership validation |
| **Privilege Escalation** | User role | Admin operations | RBAC enforcement + token validation |
| **Timing Attacks** | Network attacker | Credential guessing | Constant-time API key comparison |
| **Denial of Service** | Network attacker | Service unavailable | Subprocess timeouts (120s) |
| **Error Disclosure** | Network attacker | Information leakage | Generic error messages + server logging |
| **Weak Encryption** | Storage attacker | Certificate compromise | PBKDF2 + random per-installation salt |
| **Expired Certs** | Operational error | Invalid PKI | Expiration timeline, audit logs |

---

## Implemented Security Controls

### 1. CSRF Protection (Issue #2 - Critical)

**Attack**: Cross-Origin Request Forgery via form submission from attacker website

**Defense**:
- Primary: SameSite=strict cookies prevent cross-site cookie inclusion
- Secondary: X-Requested-With header check for additional protection
- Implementation:
  ```python
  @app.middleware("http")
  async def csrf_protection_middleware(request: Request, call_next):
      # POST/PUT/DELETE/PATCH require session cookie OR X-Requested-With header
      # Static and auth endpoints exempt
  ```

**Testing**: POST requests without session cookie must include `X-Requested-With: XMLHttpRequest` header

---

### 2. Secrets Management (Issue #1 - Critical)

**Vulnerability**: Real secrets (.env, API keys, JWT secret) committed to source control

**Defense**:
- `.env` in `.gitignore` prevents accidental commits
- `.env.example` with placeholder values for documentation
- Secrets never appear in logs or error messages
- Encryption salt: `PKI_ENCRYPTION_SALT` (32-byte random, unique per installation)

**Deployment**:
```bash
# Generate random salt once at installation
SALT=$(openssl rand -base64 32)
export PKI_ENCRYPTION_SALT=$SALT
# Store in .env securely (not in source control)
```

---

### 3. Authentication & Session Management (Issue #19)

**Implementation**:
- JWT tokens signed with HS256 (HMAC-SHA256)
- Issued via `/auth/session` endpoint after API key validation
- Stored in HTTPOnly, Secure, SameSite=strict cookie
- Session identifier: `{role}-{uuid}` (e.g., `admin-550e8400-e29b-41d4-a716-446655440000`)
- Default session duration: 15 minutes (configurable via PKI_SESSION_MINUTES)
- Token includes: `sub` (session ID), `role`, `iat`, `exp`, `iss`

**Security**:
- Constant-time API key comparison (prevents timing attacks)
- Leeway: 30 seconds for clock skew
- Signature verification required for all requests
- Expired tokens redirect to login

---

### 4. Error Disclosure Prevention (Issue #7)

**Vulnerability**: Stack traces, paths, database errors exposed to users

**Defense**:
- All exception handlers catch errors
- Generic message to user: "An unexpected error occurred. Please contact an administrator."
- Full error details logged server-side with context:
  ```python
  except Exception as e:
      logger.exception("Operation failed for org_id=%s", org_id)
      return error_response("generic_message")
  ```
- Logs include: timestamp, operation, org_id, cert_id, full exception chain

**Impact**: Reduces information leakage for reconnaissance attacks

---

### 5. Security Response Headers (Issue #8)

**Headers Added**:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Frame-Options` | DENY | Prevents clickjacking |
| `X-Content-Type-Options` | nosniff | Prevents MIME sniffing |
| `Referrer-Policy` | strict-origin-when-cross-origin | Controls referrer leakage |
| `Content-Security-Policy` | `default-src 'self'` | Restricts resource loading |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | HSTS for 2 years (HTTPS only) |

**Middleware**:
```python
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    # Adds all headers to every response
    # HSTS only sent over HTTPS
```

---

### 6. Subprocess Execution Safety (Issue #6)

**Vulnerability**: Hung child processes block worker threads indefinitely (DoS)

**Defense**:
- Timeout: 120 seconds (configurable via `PKI_SUBPROCESS_TIMEOUT_SECONDS` env var)
- Applied to all subprocess.run() calls:
  - Certificate creation via create_cert.py
  - Organization folder initialization
  - CRL generation

**Error Handling**:
```python
try:
    result = subprocess.run(..., timeout=SUBPROCESS_TIMEOUT)
except subprocess.TimeoutExpired:
    logger.exception("Subprocess timed out after %ds", SUBPROCESS_TIMEOUT)
    raise TimeoutError("Operation timed out")
```

---

### 7. Role-Based Access Control (RBAC) (Issue #13)

**Roles**:
- **admin**: Full access (create orgs, all certs, revoke, manage users)
- **manager**: End-entity cert creation + read operations
- **user**: Read-only access (view certs, timeline)

**Enforcement**:
- Per-route rules defined in `backend/config/rbac.json`
- Middleware checks `require_roles_config()` on protected endpoints
- Roles extracted from JWT `role` claim

**Protected Routes**:
```json
{
  "POST /create-organization": ["admin"],
  "GET /organizations/{org_id}/manage": ["admin", "manager", "user"],
  "GET /api/check-consistency": ["admin", "manager"],
  "POST /organizations/{org_id}/revoke": ["admin"]
}
```

**Public Endpoints** (No Authentication Required):
- **CRL Distribution Points**: `/organizations/{org_id}/crl/*`
  - Reason: Browsers and applications need to fetch CRLs without authentication to validate certificate revocation status
  - This is required by RFC 5280 and X.509 PKI standards
  - CRL contents are non-sensitive (only lists revoked certificate serial numbers)
- **Login/Logout**: `/auth/login`, `/auth/session`, `/auth/logout`
  - Required for session establishment

---

### 8. Input Validation (Issue #5)

**Revocation Reason Validation**:
- RFC 5280 §5.3.1 specifies 9 valid reason codes
- Allowlist validation before database write:
  ```python
  VALID_REVOCATION_REASONS = frozenset({
      "unspecified", "keyCompromise", "caCompromise", "affiliationChanged",
      "superseded", "cessationOfOperation", "certificateHold",
      "removeFromCRL", "privilegeWithdrawn", "aACompromise"
  })
  if reason not in VALID_REVOCATION_REASONS:
      raise HTTPException(status_code=422, detail="Invalid reason")
  ```

**Certificate Name Validation**:
- Input length limits enforced
- Special characters sanitized for folder names
- Subject DN fields validated against policy

---

### 9. Cross-Organization Boundary Protection (Issue #3)

**Vulnerability**: Authenticated user could revoke certs in other organizations

**Defense**:
- All certificate operations validate organization ownership first:
  ```python
  cert = db.get_certificate_by_id_for_organization(cert_id, org_id)
  if not cert:
      logger.warning("Cross-org access attempt for cert_id=%s, org_id=%s", cert_id, org_id)
      raise HTTPException(status_code=403)
  ```
- Applied to: renewal, revocation, viewing, downloading
- Database constraints enforce org_id foreign keys

---

### 10. CA Hierarchy Protection (Issue #12)

**Vulnerability**: Revoking a CA with active subordinates invalidates entire chain

**Defense**:
- Before revocation, query for active child certificates:
  ```python
  children = db.get_active_certificates_by_issuer(cert_id)
  if children:
      return error_page("Cannot revoke CA with active children", children)
  ```
- User must revoke children first (depth-first revocation)
- Prevents accidental PKI breakage

---

### 11. Encryption at Rest (Issue #9)

**Algorithm**: Fernet (AES-128-CBC + HMAC-SHA256)
- **Key Derivation**: PBKDF2 with SHA256
- **Iterations**: 480,000
- **Salt**: 32-byte random, unique per installation (`PKI_ENCRYPTION_SALT`)

**Files Encrypted**:
- All PEM certificate files (*.pem.enc)
- Private key files (*.key.enc)
- Sensitive artifacts in `/data/org_*/` directories

**Implementation**:
```python
def _get_fernet() -> Fernet:
    salt = base64.b64decode(os.environ.get("PKI_ENCRYPTION_SALT"))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(key.encode()))
    return Fernet(derived_key)
```

**Security**:
- Random salt eliminates pre-computed dictionary attacks
- PBKDF2 iterations slow brute-force attempts (480,000 ≈ 0.5s/attempt)
- Key derivation unique to each installation

---

### 12. Audit Logging (Issue #10)

**Information Logged**:
- Operation type (create_root_ca, revoke_certificate, etc.)
- Session identity: `{role}-{uuid}` (from JWT sub claim)
- Organization and certificate IDs
- Timestamp (UTC)
- Result (success/failure)
- IP address (optional, from request)

**Example Log Entry**:
```
2026-03-03T14:23:45.123Z INFO: Operation=[create_root_ca] user=[admin-550e8400] org_id=5 cert_id=42 status=success
```

**Retention**:
- Stored in SQLite `audit_log` table
- No automatic purge (retention policy TBD)
- Queryable via database or log export

---

### 13. Hash Algorithm Selection (Issue #15)

**Removed**: SHA-1 (deprecated in RFC 9155)
**Available**:
- SHA-256 (default for most certs)
- SHA-384
- SHA-512

**Enforcement**:
```python
def parse_hash(name: str) -> hashes.HashAlgorithm:
    if name == "sha1":
        raise ValueError("SHA-1 not permitted (RFC 9155)")
    # ... use modern hash
```

---

### 14. Dependency Management (Issue #14)

**Pinned Versions**:
```
fastapi==0.128
sqlalchemy==2.0.34
cryptography==46.0.5     # Security-critical
PyJWT==2.10.1
```

**Update Policy**:
- Security patches applied immediately
- Minor version updates quarterly with testing
- Major versions reviewed for compatibility
- Cryptography updates require release notes review

---

### 15. Certificate Validation (Database Level)

**Constraints**:
- `organizations.org_dir` — UNIQUE (prevent folder collisions)
- `organizations.name` — UNIQUE (prevent duplicate org names)
- `certificates.cert_uuid` — UNIQUE (stable artifact identifiers)
- `certificates.serial_number` — UNIQUE per issuer (X.509 requirement)
- `certificates.issuer_cert_id` — Foreign key to organizations

**Enforcement**:
```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY,
    organization_id INTEGER NOT NULL REFERENCES organizations(id),
    issuer_cert_id INTEGER REFERENCES certificates(id),
    cert_uuid VARCHAR(36) NOT NULL UNIQUE,
    serial_number VARCHAR(40) NOT NULL,
    status TEXT CHECK (status IN ('active', 'revoked', 'superseded')),
    UNIQUE(organization_id, serial_number)
);
```

---

## Audit & Logging

### Logged Operations

| Operation | Details Logged |
|-----------|----------------|
| Create Organization | org_id, name, user, timestamp |
| Create Root CA | cert_id, issuer_name, subject_dn, user, timestamp |
| Create Intermediate CA | cert_id, issuer_id, issuer_name, user, timestamp |
| Create End-Entity Cert | cert_id, cert_type, issuer_id, SAN, user, timestamp |
| Revoke Certificate | cert_id, reason, user, timestamp, affected_crls |
| Renew Certificate | old_cert_id, new_cert_id, user, timestamp |

### Log Storage

- **Location**: SQLite `audit_log` table
- **Rotation**: Manual export recommended for long-term retention
- **Retention**: No automatic purge (policy TBD)
- **Searchable**: Via database queries (org_id, user, cert_id, date range)

### Log Format

```
timestamp: 2026-03-03T14:23:45.123456Z
operation: create_root_ca
user_name: admin-550e8400-e29b-41d4-a716-446655440000
organization_id: 5
certificate_id: 42
details: {
  "cn": "Example Root CA",
  "issuer_name": "Example Root CA",
  "days": 7300
}
```

---

## Deployment Security

### Pre-Deployment Checklist

- [ ] Review all source code changes
- [ ] Run full test suite: `pytest tests/` (expect 40/40 passing)
- [ ] Rotate all API keys from .env
- [ ] Generate unique encryption salt: `openssl rand -base64 32`
- [ ] Configure HTTPS with valid TLS certificate
- [ ] Set environment variables (don't commit .env):
  ```bash
  export PKI_HOST=0.0.0.0          # or specific IP
  export PKI_PORT=8000
  export PKI_BASE_URL=https://pki.example.com
  export PKI_COOKIE_SECURE=true
  export PKI_COOKIE_SAMESITE=strict
  export ENCRYPTION_KEY=<32+ random chars>
  export PKI_ENCRYPTION_SALT=<base64-encoded 32 bytes>
  export PKI_API_KEY_ADMIN=<strong random key>
  export PKI_API_KEY_MANAGER=<strong random key>
  export PKI_API_KEY_USER=<strong random key>
  export PKI_JWT_SECRET=<strong random 32+ chars>
  ```

### Runtime Security

**HTTPS Only**:
- Set `PKI_COOKIE_SECURE=true` (default since Mar 2026)
- Configure TLS 1.2+ with strong ciphers
- Use certificates from trusted CA
- HSTS header will be sent automatically (max-age=2 years)

**Database Security**:
- SQLite file permissions: 0600 (owner read/write only)
- Backup encrypted copies to secure location
- Regular integrity checks: `PRAGMA integrity_check;`

**Filesystem Security**:
- `/data/org_*` folders: 0700 (owner only)
- PEM files encrypted at rest (Fernet)
- Backup encrypted copies separately from database

**API Key Management**:
- Rotate API keys annually
- Different keys per environment (dev/staging/prod)
- Revoke compromised keys immediately
- No API keys in logs or error messages

### Production Hardening

**Reverse Proxy** (nginx/Apache):
```nginx
# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req zone=api burst=20 nodelay;

# Security headers (supplementary to app)
add_header X-Content-Type-Options "nosniff";
add_header X-Frame-Options "DENY";

# TLS
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

**Web Application Firewall** (ModSecurity):
- Protect against common web attacks (SQL injection, XSS)
- Log suspicious requests for analysis
- Set to "detect" mode initially, then "block"

**Monitoring**:
- Alert on authentication failures (5+ in 1 minute)
- Alert on CSRF rejections (possible attack)
- Alert on errors (500+ status codes)
- Monitor subprocess timeout rate (should be 0)
- Track API usage by role (anomaly detection)

---

## Incident Response

### Security Incident Procedure

**If API Keys Compromised**:
1. Immediately revoke all exposed API keys in production
2. Generate new keys
3. Distribute new keys to authorized users/services
4. Review audit logs for unauthorized access
5. Rotate encryption key if long-term exposure suspected

**If Private Key Compromised**:
1. Immediately revoke the certificate
2. Assess impact (who trusted this cert?)
3. Issue replacement certificate
4. Update CRL and distribute
5. Notify all parties that relied on compromised cert

**If Database Breached**:
1. Take database offline temporarily
2. Restore from encrypted backup
3. Change all secrets (API keys, JWT secret, encryption salt)
4. Rotate encryption key if encrypted-at-rest was bypassed
5. Review audit logs for unauthorized operations

**If Source Code Leaked**:
1. Rotate all credentials (API keys, JWT secret, salt)
2. Invalidate all active JWT sessions
3. Force password reset for all user accounts
4. Review exposed code for hardcoded secrets
5. Deploy patched version immediately

### Reporting Security Issues

**Do not open public GitHub issues for security vulnerabilities.**

Instead, email: `security@example.com` (configure before deployment)

Include:
- Vulnerability description
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

**Response SLA**: 48 hours acknowledgment, 7 days patch release

---

## Compliance & Standards

### RFC Compliance

- **RFC 5280**: X.509 PKI Certificate and CRL Profile
  - Certificate structure and extensions
  - CRL generation and format
  - Revocation reasons (9 valid types)

- **RFC 6265**: HTTP State Management Mechanism
  - Cookie attributes (Secure, HttpOnly, SameSite)
  - Session management

- **RFC 7230-7235**: HTTP/1.1 Semantics and Content
  - Security headers (Content-Security-Policy, etc.)

- **RFC 7539**: ChaCha20 and Poly1305
  - Reference for modern AEAD (not used; using Fernet/AES-128-CBC)

- **RFC 9155**: Algorithm Agility for DNSSEC
  - Deprecates SHA-1 for certificate issuance

### OWASP Top 10 (2021)

| Category | Mitigation |
|----------|-----------|
| A01: Broken Access Control | RBAC + org boundary validation |
| A02: Cryptographic Failures | PBKDF2 + random salt, Fernet encryption |
| A03: Injection | Parameterized queries (SQLAlchemy) |
| A04: Insecure Design | Design review completed, threat model documented |
| A05: Security Misconfiguration | Secure defaults (HTTPS, SameSite=strict) |
| A06: Vulnerable Components | Dependencies pinned, security patches applied |
| A07: Authentication Failure | JWT + constant-time key comparison |
| A08: Software Data Integrity | HTTPS only, signature verification |
| A09: Logging & Monitoring | Audit logs with session identity |
| A10: SSRF | Not applicable (no external resource requests) |

---

## Security by Design

### Immutable Audit Trail

All certificate operations are recorded with:
- **User identity** (from JWT sub claim: `{role}-{uuid}`)
- **Timestamp** (UTC, precise)
- **Operation** (create, revoke, renew)
- **Resource ID** (cert_id, org_id)
- **Result** (success/failure)

This enables:
- Non-repudiation (user cannot deny operation)
- Forensic analysis (who did what when)
- Compliance reporting (who accessed what)

### Principle of Least Privilege

- **User role**: Read-only access (view certificates, timeline)
- **Manager role**: Can create end-entity certificates
- **Admin role**: Full control (create orgs, manage users, revoke)

Each operation checks role before execution.

### Defense in Depth

| Layer | Control |
|-------|---------|
| **Network** | HTTPS/TLS 1.2+, no cleartext transmission |
| **Session** | HTTPOnly + Secure + SameSite=strict cookies |
| **API** | CSRF header check, RBAC enforcement |
| **Application** | Input validation, org boundary checks, error handling |
| **Data** | Parameterized queries, constraint enforcement |
| **Storage** | Encryption at rest (Fernet), filesystem permissions |
| **Audit** | Immutable logs with user identity |

---

## Glossary

- **PBKDF2**: Password-Based Key Derivation Function (slow, intended for key derivation)
- **Fernet**: Symmetric encryption (AES-128-CBC + HMAC-SHA256)
- **JWT**: JSON Web Token (signed claims with user identity)
- **RBAC**: Role-Based Access Control (permissions tied to roles)
- **CSRF**: Cross-Site Request Forgery (attacker tricks user into unintended request)
- **SameSite**: Cookie attribute preventing cross-site cookie inclusion
- **HTTPOnly**: Cookie attribute preventing JavaScript access
- **Secure**: Cookie attribute forcing HTTPS-only transmission
- **X-Requested-With**: Custom HTTP header identifying AJAX requests
- **CSP**: Content Security Policy (restricts resource loading)
- **HSTS**: HTTP Strict-Transport-Security (forces HTTPS)

---

## Further Reading

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)

---

**For questions or security concerns, contact**: `security@example.com`
