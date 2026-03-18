# Certificate Error Handling Analysis

**Date**: 2026-03-18
**Status**: VERIFICATION COMPLETE

## Summary

This document verifies whether certificates can be partially persisted (in database or on disk) if errors occur during certificate creation.

## Current Flow

### Certificate Creation Pipeline (All Types: Root, Intermediate, End-Entity)

The flow for all three certificate creation endpoints (`create_root_ca`, `create_intermediate_ca`, `create_end_entity`) follows this pattern:

```
1. Subprocess runs: _run_create_cert_subprocess(params)
   └─ Creates certificate files on disk (success or fail)

2. Workspace initialization: init_*_workspace(...)
   └─ Returns dict with paths to created files

3. Metadata extraction: db.extract_certificate_metadata(...)
   └─ Reads certificate file from disk
   └─ Parses all extensions and attributes

4. Database insert: db.create_certificate_with_extensions(cert_info)
   └─ Wrapped in SQLAlchemy transaction (engine.begin())
   └─ Inserts base certificate + all extensions atomically

5. Post-creation: audit logging, CRL generation, renewal revocation
```

## Error Scenarios & Current Behavior

### Scenario 1: Subprocess Fails (CalledProcessError/TimeoutError)
**Status**: ✅ SAFE

- Exception caught at line 2180-2212 (intermediate), 1957-1978 (root), 2448-2470 (end-entity)
- Certificate files are NOT created by subprocess
- No database entry is created
- Error page returned to user
- **Result**: No orphaned files, no database entries

### Scenario 2: Metadata Extraction Fails
**Status**: ⚠️ RISKY - FILES ORPHANED

**Code Location**: app.py line 2140-2150 (intermediate), similar for root/end-entity

```python
# Files created by subprocess (line 2130)
create_output = _run_create_cert_subprocess(params)

# Metadata extraction reads from disk (line 2140)
cert_info = db.extract_certificate_metadata(
    ...
    cert_path=ws["crt_path"],  # File expected to exist
    ...
)
# If extract_certificate_metadata raises exception here:
# - Files exist on disk (orphaned)
# - Database entry NOT created
# - Generic Exception handler (line 2202-2212) catches and displays error
```

**Potential causes**:
- Corrupted certificate file
- Missing required extensions
- Cryptography library parsing failure
- File permission issues after subprocess creates files

**Current handling**: Caught by generic `except Exception` handler, but no cleanup occurs.

### Scenario 3: Database Insert Fails
**Status**: ✅ SAFE (atomicity guaranteed)

**Code Location**: app.py line 2152 (intermediate), db.py line 656-701

```python
def create_certificate_with_extensions(cert_info: dict) -> int:
    with engine.begin() as conn:  # ← Transaction context
        # Insert base certificate
        result = conn.execute(
            text("INSERT INTO certificates (...)"),
            base_cert,
        )
        cert_id = result.lastrowid

        # Insert extensions (SANs, BasicConstraints, KeyUsage, EKU, etc.)
        _insert_subject_alternative_names(conn, cert_id, ...)
        _insert_basic_constraints(conn, cert_id, ...)
        # If ANY insert fails, entire transaction rolls back
```

**Current handling**:
- `engine.begin()` creates an atomic transaction
- If ANY insert fails, entire operation rolls back
- No database entry created if any exception occurs
- Exception propagates to caller

**Result**: Files exist on disk, but database stays consistent.

### Scenario 4: Audit Logging Fails
**Status**: ✅ SAFE (non-fatal)

**Code Location**: app.py line 2156-2159

```python
try:
    db.log_certificate_operation(cert_id, "created", user_name, ...)
except Exception as e:
    logger.warning(f"Audit log failed (non-fatal): {e}")
```

Database entry already created, certificate considered valid. Audit log failure doesn't affect certificate.

### Scenario 5: CRL Generation Fails
**Status**: ✅ SAFE (non-fatal)

**Code Location**: app.py line 2161-2163 (intermediate), 1928-1930 (root)

```python
if created_intermediate:
    _trigger_crl_regeneration(org, cert_id, created_intermediate, ...)
```

Not in try-except, but if this fails:
- Certificate already committed to database
- Error would be caught by outer exception handler
- Database entry exists, but CRL not generated (non-critical)

### Scenario 6: Renewal Revocation Fails
**Status**: ⚠️ RISKY - DATABASE INCONSISTENCY POSSIBLE

**Code Location**: app.py line 2166 (intermediate), 1933 (root)

```python
renewal_error = _handle_renewal_revocation(org, org_id, renewal_of_cert_id)
if renewal_error:
    # Error page shown, but new cert ALREADY IN DATABASE
    return templates.TemplateResponse("error.html", {...})
```

**Issue**: If renewal operation encounters error:
- New certificate is already committed to database
- Previous certificate may not have been revoked as intended
- User sees error but certificate exists in database

## Data Integrity Issues Identified

### Issue 1: Orphaned Files (Scenario 2)
**Severity**: MEDIUM

Files created on disk but no database entry:
- No way to query them via API
- Consume disk space indefinitely
- Manual cleanup required via `backend/folder.py delete-files`
- Not discoverable unless filesystem is scanned directly

### Issue 2: Incomplete Renewal (Scenario 6)
**Severity**: MEDIUM

New certificate created in database but previous certificate not revoked:
- Certificate chain inconsistency
- Could lead to multiple valid certificates for same entity
- Manual revocation required

### Issue 3: No Automatic Recovery
**Severity**: LOW

No mechanism exists to:
- Detect orphaned files
- Clean up partial creations
- Reconcile database vs filesystem
- Flag incomplete operations for admin review

## Current Mitigations

### ✅ Working
1. **Transaction atomicity**: Database inserts are wrapped in `engine.begin()` transaction
   - No partial database entries possible
   - Either full entry created or none
   - Extensions inserted atomically with base certificate

2. **Subprocess isolation**: File creation is separate process
   - Failure in file creation doesn't affect database
   - Subprocess exit codes checked
   - Errors logged

3. **Error pages**: All scenarios return error page to user
   - User knows something failed
   - No silent failures

### ❌ Missing
1. **File cleanup on error**: No mechanism to remove orphaned files
   - After metadata extraction fails, files remain
   - No cleanup in finally block
   - No cleanup in exception handlers

2. **Renewal atomicity**: New certificate and revocation not in same transaction
   - Two separate database operations
   - No rollback if second fails

3. **Consistency validation**: No post-creation validation
   - Files not verified to match database entry
   - No checksum or stat comparison

4. **Recovery/Audit**: No tracking of failed operations
   - Failed certificate creations not logged in structured way
   - No dashboard showing orphaned files
   - Cleanup requires manual filesystem inspection

## Recommendations

### Priority 1: File Cleanup on Error
Wrap file operations in try-finally or use transaction-like pattern:

```python
# Current (risky)
create_output = _run_create_cert_subprocess(params)
ws = init_intermediate_workspace(...)
cert_info = db.extract_certificate_metadata(...)  # ← Can fail
cert_id = db.create_certificate_with_extensions(cert_info)

# Recommended
created_paths = None
try:
    create_output = _run_create_cert_subprocess(params)
    ws = init_intermediate_workspace(...)
    created_paths = {
        'crt_path': ws['crt_path'],
        'key_path': ws['key_path'],
        'csr_path': ws['csr_path'],
        'pwd_path': ws['pwd_path'],
    }
    cert_info = db.extract_certificate_metadata(...)
    cert_id = db.create_certificate_with_extensions(cert_info)
    created_paths = None  # Mark as committed
except Exception:
    # Clean up files if metadata extraction or DB failed
    if created_paths:
        for path in created_paths.values():
            try:
                Path(path).unlink(missing_ok=True)
            except Exception as cleanup_err:
                logger.error(f"Failed to clean up {path}: {cleanup_err}")
    raise
```

### Priority 2: Atomic Renewal
Combine new certificate creation and old certificate revocation:

```python
# In same transaction
with db.engine.begin() as conn:
    # Create new certificate
    # Revoke old certificate
    # Either both succeed or both rollback
```

### Priority 3: Consistency Validation
After certificate creation:

```python
# Verify files match database entry
cert_from_db = db.get_certificate_by_id_for_organization(cert_id, org_id)
for path_key, path_val in ws.items():
    if path_key == 'dir_root' or not path_val:
        continue
    if not Path(path_val).exists():
        raise ConsistencyError(f"Created cert missing file: {path_val}")
```

### Priority 4: Admin Discovery Tool
Create utility to find and optionally clean orphaned files:

```python
def find_orphaned_certificates(org_id: int) -> List[Path]:
    """Find cert files on disk not in database."""
    # Scan filesystem for .pem.enc, .key.enc, .csr.enc, .pwd.enc
    # Query database for cert_path, key_path, csr_path, pwd_path
    # Return files without DB entry
```

## Test Coverage Needed

Add tests for these scenarios:
1. Metadata extraction failure → verify files cleaned up
2. Database insert failure → verify files still exist, DB empty
3. Renewal error → verify previous cert revoked
4. Orphaned file recovery → verify cleanup tool works
5. File vs database consistency → verify validation

## Conclusion

**Current state**: Certificates cannot be partially created in the database (atomicity guaranteed), but files may be orphaned on disk if errors occur after subprocess succeeds.

**Risk level**: MEDIUM
- Database remains consistent
- Files orphaned on disk (low impact, manual cleanup available)
- Renewal operations could leave inconsistencies (requires attention)

**Action items**:
1. Add file cleanup on error (priority 1)
2. Review renewal revocation logic (priority 2)
3. Add consistency validation (priority 3)
4. Create orphaned file detection tool (priority 4)
