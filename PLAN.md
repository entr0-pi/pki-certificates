# Consistency Tests Enhancement Plan

## Objective
Add new consistency checks to `scripts/check_consistency.py` to improve data integrity validation and catch issues earlier in the PKI lifecycle.

## Current Coverage (After Recent Changes)
- ✓ Certificate file existence
- ✓ Subject/issuer consistency
- ✓ Serial number validation and duplicates
- ✓ Validity date ranges
- ✓ Type/policy consistency
- ✓ Artifact path consistency
- ✓ Private key-certificate matching (except root CAs with dual passwords)
- ✓ CSR consistency
- ✓ Extension consistency (SAN, BC, KU, EKU)
- ✓ CRL semantic consistency

## Proposed New Tests

### 1. CRL Existence & Validity (HIGH PRIORITY)
**Description:** Verify all issuer CAs have valid CRL files
- Check each root CA has a CRL file
- Check each intermediate CA has a CRL file
- Validate CRL files are parseable x509 CRL objects
- Verify CRL issuers match issuing certificate subject
- Check CRL signatures are valid (match issuer public key)
- **Metric:** `crl_validity_checks`

**Why:** Directly addresses the recent ROOT-CA CRL generation bug. Ensures CRL bundle completeness.

---

### 2. UUID Uniqueness & Consistency (HIGH PRIORITY)
**Description:** Validate cert_uuid usage across the system
- Verify all certs have cert_uuid populated (except legacy ones)
- Check for duplicate UUIDs within organization
- Verify UUID format (valid UUID v4)
- Verify UUID file references exist (cert, key, csr, crl paths use UUID)
- **Metric:** `uuid_consistency_checks`

**Why:** New UUID feature requires integrity checks. Catches broken references.

---

### 3. Certificate Chain Validation (MEDIUM PRIORITY)
**Description:** Verify issuer-issued relationships form valid chains
- For each non-root cert: issuer_cert_id must exist and be a CA
- Verify no circular chains (cert cannot issue itself)
- Verify chain depth doesn't exceed policy limits (e.g., root→intermediate→end-entity only)
- Verify intermediate issuers are signed by root CA
- **Metric:** `chain_validation_errors`

**Why:** Catches orphaned certs or misconfigured hierarchies.

---

### 4. CRL Revocation List Accuracy (MEDIUM PRIORITY)
**Description:** Verify CRL contents match database revocation state
- For each revoked cert: verify it appears in issuer's CRL
- Verify CRL revocation dates match database revoked_at
- Verify revocation reasons in CRL match database reasons
- Check no active certs appear in CRL (data corruption detection)
- **Metric:** `crl_revocation_mismatches`

**Why:** Catches sync issues between DB and CRL files.

---

### 5. Encryption & Encoding Validation (MEDIUM PRIORITY)
**Description:** Verify all encrypted files are properly formatted
- Test decryption of all .enc certificate files
- Test decryption of all .enc key files
- Test decryption of all .enc CRL files
- Verify password files are readable and decode to valid formats
- **Metric:** `encryption_validation_failures`

**Why:** Detects file corruption or encryption issues early.

---

### 6. Certificate Field Completeness (LOW PRIORITY)
**Description:** Verify required certificate fields are populated
- Check all certs have: CN, C, O, ST, L
- Verify email format when present
- Check subject matches policy constraints (match/supplied/optional)
- Verify SAN is present for server certs if policy requires it
- **Metric:** `field_completeness_errors`

**Why:** Ensures policy compliance and certificate usability.

---

### 7. Dual Password Consistency (NEW - related to recent feature)
**Description:** Validate root CA dual password setup
- Verify all root CAs have .pwd.enc file
- Verify password file can be read and decoded to valid hex
- Verify filesystem password length is 32 bytes (hex decoded)
- **Metric:** `dual_password_consistency_errors`

**Why:** Ensures root CA password derivation will work correctly.

---

## Implementation Order
1. **Phase 1 (High Priority):** CRL Existence & Validity, UUID Uniqueness
   - Directly address recent bugs
   - Quick wins with high impact

2. **Phase 2 (Medium Priority):** Certificate Chain, CRL Accuracy, Encryption Validation
   - Core data integrity checks
   - Broader coverage

3. **Phase 3 (Low Priority):** Field Completeness, Dual Password Consistency
   - Polish and compliance checks
   - Policy enforcement

## Configuration Updates
Add new metrics to stats dict in ConsistencyChecker:
```python
"crl_validity_checks": 0,
"crl_validity_failures": 0,
"uuid_consistency_errors": 0,
"chain_validation_errors": 0,
"crl_revocation_mismatches": 0,
"encryption_validation_failures": 0,
"field_completeness_errors": 0,
"dual_password_consistency_errors": 0,
```

## Testing Strategy
- Run consistency check on clean org (should pass all)
- Introduce failures: delete CRL, corrupt encryption, invalid UUID
- Verify each test catches its specific issue
- Verify error messages are actionable for operators

## Success Criteria
- ✓ All proposed tests implemented
- ✓ No false positives on clean data
- ✓ Clear error messages for each failure type
- ✓ Metrics tracked in summary output
- ✓ Documentation updated with new checks
