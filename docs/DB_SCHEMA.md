# PKI Database Schema (Implementation Status)

This document is the **trustworthy status view** of the PKI database model as of the current codebase.

Source of truth:
- Schema DDL: `database/pki_schema.sql`
- Runtime usage: `backend/db.py`, `backend/app.py`

Status labels:
- `Implemented`: actively read/written by current app flows
- `Partially Implemented`: table/object exists and is touched in limited ways
- `Planned`: table/object exists in schema but is not actively used by current app flows

---

## Snapshot

### Tables

| Table | Status | Notes |
|---|---|---|
| `organizations` | Implemented | Created/read/listed by app. |
| `certificates` | Implemented | Primary certificate metadata store; issuance + revocation state updates. |
| `certificate_audit_log` | Partially Implemented | Insert helper exists in `db.py`, but not wired into main app flows. |
| `subject_alternative_names` | Implemented | Populated on cert creation; read by popup with PEM fallback for legacy certs. |
| `certificate_extensions` | Implemented | Generic extension storage; populated on cert creation for audit trail. |
| `basic_constraints` | Implemented | Normalized extension storage; populated on cert creation, read by popup. |
| `key_usage` | Implemented | Normalized extension storage; populated on cert creation, read by popup. |
| `extended_key_usage` | Implemented | Normalized extension storage; populated on cert creation, read by popup. |
| `crls` | Implemented | Populated during revocation after CRL generation succeeds. |
| `revoked_certificates` | Implemented | Populated during revocation; links CRL history to revoked certs. |

### Views

| View | Status | Notes |
|---|---|---|
| `certificate_chains` | Planned | Defined in schema; not used by app code. |
| `certificate_summary` | Planned | Defined in schema; not used by app code. |
| `certificates_expiring_soon` | Planned | App computes expiring certs directly from `certificates`. |
| `ca_hierarchy` | Planned | Defined in schema; not used by app code. |

### Indexes

| Index Group | Status | Notes |
|---|---|---|
| `certificates` indexes | Implemented | Useful for current read paths by org/type/status/issuer. |
| Extension table indexes | Planned | Tables not actively populated. |
| Audit table indexes | Partially Implemented | Table lightly used at helper level only. |

---

## Implemented Data Model (What app actually relies on)

### 1. `organizations` (`Implemented`)

Stores organization identity and folder mapping.

- Used by:
  - create organization
  - list organizations
  - fetch by id / by directory

### 2. `certificates` (`Implemented`)

Stores all issued cert metadata for:
- `root`
- `intermediate`
- `server`
- `client`
- `email`

Actively used for:
- certificate listing and dashboard stats
- chain relation via `issuer_cert_id`
- revocation status (`status`, `revoked_at`, `revocation_reason`)
- expiring certificate queries

### 3. `certificate_audit_log` (`Partially Implemented`)

- `db.log_certificate_operation(...)` exists.
- Main issuance/revocation web flows do not currently call it.

---

## Planned / Not Yet Wired

These schema objects are present and valid in DDL, but current runtime flows do not persist/query them:

- views: `certificate_chains`, `certificate_summary`, `certificates_expiring_soon`, `ca_hierarchy`

### Recently Implemented (as of Feb 2026)

The following extension and CRL tables are now **Implemented**:
- `subject_alternative_names` — populated on cert creation; read by popup with PEM fallback
- `certificate_extensions` — generic extension audit trail
- `basic_constraints` — normalized extension storage
- `key_usage` — normalized extension storage
- `extended_key_usage` — normalized extension storage with OID→name mapping
- `crls` — CRL metadata including generation timestamp and next update time
- `revoked_certificates` — per-CRL revocation history with linkage to revoked certs

**Impact**: Certificate extension details (SAN, KU, EKU, BasicConstraints) are now persisted to DB during issuance and retrieved preferentially by popup/metadata routes (with PEM parse fallback for legacy certs). CRL artifacts are now tracked relationally, not just on disk.

---

## Current App-Safe Query Examples

These examples reflect objects actively used today.

### List certificates for one org

```sql
SELECT id, cert_name, cert_type, issuer_cert_id, status, not_after
FROM certificates
WHERE organization_id = :org_id
ORDER BY created_at DESC, id DESC;
```

### Check chain linkage quality

```sql
SELECT cert_type,
       COUNT(*) AS total,
       SUM(CASE WHEN issuer_cert_id IS NULL THEN 1 ELSE 0 END) AS missing_issuer
FROM certificates
GROUP BY cert_type;
```

### Find revoked certificates signed by one issuer

```sql
SELECT id, serial_number, revoked_at, revocation_reason
FROM certificates
WHERE issuer_cert_id = :issuer_cert_id
  AND status = 'revoked'
ORDER BY revoked_at;
```

### Organization and certificate counts (health-like)

```sql
SELECT (SELECT COUNT(*) FROM organizations) AS organizations,
       (SELECT COUNT(*) FROM certificates) AS certificates;
```

---

## Notes for Contributors

- If you add writes to any currently planned table, update this document status in the same PR.
- If you switch app logic to read from views, mark those views `Implemented`.
- Keep this doc aligned with both `database/pki_schema.sql` and runtime behavior in `backend/db.py` / `backend/app.py`.
