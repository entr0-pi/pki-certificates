# End-to-End Web App Test Plan (Step-by-Step)

Use this in order, and record each step as PASS/FAIL with screenshot + note.

## Phase 0: Authentication and Session

1. Start app and open `http://localhost:<port>/auth/login`.
2. Confirm unauthenticated access to `/` redirects to `/auth/login`.
3. Try invalid API key and confirm login error message.
4. Log in with `admin` API key.
5. Confirm landing page shows role badge `admin`.
6. Click `Logout` and confirm you return to login page.
7. Log in again with `admin` for full functional run.

## Phase 1: Landing + Organization Management

1. On `/`, verify organization cards load (or empty state with create CTA).
2. If no org exists, create one from modal (`Organization Name` required).
3. If org exists, create an additional org via `Create Organization` button.
4. **Organization Creation Details**:
   - Try creating org with duplicate name and confirm error (should be UNIQUE in DB)
   - Try creating org with very long name and confirm it's sanitized/truncated appropriately
   - Verify new org gets unique folder name (e.g., `org_<id>_<sanitized_name>`)
5. Confirm new org appears with ID and created date in card.
6. **Organization Isolation**:
   - Create 2+ orgs and create certs in each
   - Verify org A's dashboard only shows org A's certs (no cross-org leakage)
   - Try accessing org B's cert popup from org A via direct URL and confirm 403/error
7. Open one org via `Manage`.
8. Confirm dashboard header, stats, and certificate table render.
9. Confirm `Create Certificate` button is visible for admin.
10. Open `CRL Downloads` menu and verify both links exist (`Latest CRL`, `CRL Bundle`).
11. **Audit Trail** (if UI displays audit logs):
    - Verify org creation is logged with timestamp and user identity
    - Verify cert operations appear in org-level audit log (if available)
12. Click `Refresh` and confirm page reloads without errors.

## Phase 2: Unified Certificate Creation

1. From org dashboard, open `Create Certificate`.
2. In `Root CA` tab, confirm all compulsory fields show `*`.
3. Confirm `Certificate Valid For` and `EC Curve` also show `*`.
4. Submit with one required field empty and confirm browser blocks submission.
5. **Policy Enforcement - Root CA**:
   - Verify locked fields (if policy enforces them) are disabled/read-only
   - Try entering invalid country code (non-2-char) and confirm validation error
   - Try entering invalid email format and confirm validation error
   - Verify EC curve dropdown only shows policy-allowed curves (e.g., P-256, P-384, not invalid curves)
   - Verify default validity (e.g., 7300 days) matches policy if not overridden
6. Fill valid root data and create root cert.
7. Confirm success response and return to org dashboard.
8. Verify root cert appears in table with status `active`.
9. Open root cert popup and verify subject fields, extensions, validity., ALSO WITH OPENSSL
10. Back to `Create Certificate`, open `Intermediate CA` tab.
11. Confirm required markers and locked-field behavior (policy lock applies for subject fields).
12. **Policy Enforcement - Intermediate CA**:
    - Verify subject fields are locked/prefilled if policy requires them to match root, WITH ALL FIELDS
    - Verify issuer dropdown lists only active intermediate/root CAs (no revoked issuers) NOT RELEVANT
    - Try creating without an active issuer and confirm error
    - Verify EC curve options match policy restrictions, NEED TO CHECK WHAT IS THE LIST USED
13. Create an intermediate CA with valid values., ALSO WITH OPENSSL
14. Confirm success and presence in dashboard table.
15. Open `End-Entity` tab.
16. Check `Server` type default: SAN section visible, Email not required.
17. Switch to `Email` type: SAN hidden, Email becomes required and `*` appears.
18. Switch to `Client` type: Email optional again and `*` removed.
19. **Policy Enforcement - End-Entity**:
    - Verify subject fields reflect locked/policy-enforced values
    - Try selecting root CA as issuer and confirm error (end-entity must use intermediate)
    - Try selecting revoked intermediate as issuer and confirm error
    - Verify SAN validation (DNS names, IP format) on server cert
    - Verify email validation on email cert type
20. Create one `server` certificate with SAN entries (test multiple SAN types).
21. Create one `client` certificate., ALSO WITH OPENSSL
22. Create one `email` certificate with required email.
23. Confirm all three appear in dashboard with correct type and active status.

## Phase 3: Certificate Table, Filters, Popup, Downloads

1. Use search box with part of cert name; verify row filtering.
2. Filter by type `root`, `intermediate`, `server`, `client`, `email`.
3. Filter by status `active`.
4. Filter by expiry windows and verify badges (`critical`, `warning`, `healthy`, `expired`).
5. Open each cert `View Details` popup from row action.
6. In popup, verify **comprehensive extension rendering**:
   - **Subject fields**: CN, O, OU, C, ST, L, Email (if present)
   - **Basic Constraints**: `is_ca` flag (true for CA certs, false for end-entity), `path_length` (if present)
   - **Key Usage**: Digital Signature, Key Cert Sign, CRL Sign, Key Encipherment, etc. (display all applicable flags)
   - **Extended Key Usage (EKU)**: serverAuth, clientAuth, emailProtection, etc. (display human-readable names)
   - **Subject Alternative Names (SAN)**: For server certs, list all DNS/IP entries with types
   - **Serial Number**: Verify format and uniqueness
   - **Validity Dates**: Not Before / Not After in correct timezone
   - **Issuer**: Display issuer certificate name and chain path
7. For a cert, download `PEM` and verify file downloads.
8. For `client`/`email`, download `PKCS12` and verify file downloads.
9. For any cert, download `Chain` and verify file downloads.
10. For `server`, download `Private Key` and verify file downloads.

## Phase 4: Renewal Flow

1. From an active cert action menu, click `Renew`.
2. On renew page, verify original cert details are shown (read-only).
3. Confirm only renewal fields are editable (`New Certificate Name`, validity controls).
4. **Renewal for End-Entity (Server/Client/Email)**:
   - Renew using `Days from now` (e.g., 365 days)
   - Confirm success and redirected/returned view
   - Verify new cert exists with incremented serial number
   - Verify old cert is auto-revoked with reason `superseded`
   - Verify new cert shows in dashboard as `active` while old shows as `revoked`
5. **Renewal for Intermediate CA**:
   - Renew an intermediate CA using `Days from now`
   - Verify old intermediate is revoked and appears in CRL
   - Verify any end-entity certs issued by old intermediate still validate (chain via issuer)
6. **Date-mode Renewal**:
   - Repeat renewal for another cert using `Specific date` (e.g., 2025-12-31)
   - Verify date-mode renewal succeeds with correct validity date
   - Verify new cert's `Not After` matches the selected date (in UTC/correct timezone)
7. **Renewal Edge Cases**:
   - Try renewing an already-revoked cert and confirm error
   - Try renewing with invalid certificate name and confirm validation
   - Verify renewed cert has new UUID artifact (not same as original)

## Phase 5: Revocation + CRL

1. On org dashboard, choose an active cert and click `Revoke`.
2. In modal, test reason selection list (all options available).
3. Submit revocation with `keyCompromise`.
4. Confirm cert status becomes `revoked` in dashboard.
5. **Revocation Details**:
   - Verify revocation reason is recorded in database/audit logs
   - Try revoking the same cert again and confirm error or idempotent behavior
   - Verify revoked cert no longer appears in issuer dropdown for new end-entity certs
6. Revoke another active cert with a different reason (e.g., `superseded`).
7. Download org `Latest CRL` and confirm file is returned (PEM format).
8. Download org `CRL Bundle` and confirm archive is returned (ZIP with multiple CRLs).
9. **CRL Content Verification**:
   - Open downloaded CRL and verify revoked cert serial numbers appear
   - Verify CRL validity dates (`thisUpdate`, `nextUpdate`)
   - Verify CRL issuer matches expected CA
   - Verify CRL number increments on subsequent revocations (e.g., CRL #1, #2, #3)
   - Confirm both revoked certs (keyCompromise + superseded) appear in CRL
10. **Issuer-Specific CRL**:
    - Open issuer-specific CRL URL if available (e.g., `/crl/<issuer_uuid>`)
    - Verify response contains only revocations by that issuer
    - Verify revoked cert serials match database records

## Phase 6: Health + Consistency + Toolbox

1. On landing or org dashboard, run `Consistency Check`.
2. Confirm modal opens and API response renders test list.
3. If success, verify all checks show `OK`.
4. If failures, verify issues list appears with level and message.
5. Open `/health` as admin and verify healthy JSON/text response.
6. Open `/healthz` and verify liveness response.
7. Open `/toolbox` and verify page loads (admin only).

## Phase 7: RBAC Validation (Critical)

Log out between roles and re-login each time.

1. Login as `manager`.
2. Confirm manager can access `/`, org dashboard, unified create page.
3. Confirm manager can create end-entity certs.
4. Confirm manager cannot create root/intermediate (UI warning or blocked action).
5. Confirm manager can renew certs.
6. Confirm manager cannot revoke certs.
7. Confirm manager can download certs (PEM/chain/PKCS12 where applicable).
8. Confirm manager cannot download plain private key.
9. Confirm manager can run consistency check.
10. Confirm manager cannot access `/toolbox` (403).
11. Login as `user`.
12. Confirm user can access landing and org dashboard.
13. Confirm user cannot access unified create page.
14. Confirm user can open certificate popup.
15. Confirm user cannot download certs/private key.
16. Confirm user cannot renew/revoke.
17. Confirm user cannot run consistency check.

## Phase 8: Negative/Validation Cases

1. **Certificate Name Validation**:
   - Try creating cert with duplicate name in same org and verify error (if enforced)
   - Try creating cert with very long name and verify sanitization (only alphanumeric, `-`, `_`)
   - Try creating cert with special chars (`!@#$%`) and verify they're stripped
2. **Subject Field Validation**:
   - Try invalid country code (3+ chars or empty) and verify validation error
   - Try invalid email format and verify validation error
   - Try very long organizational unit and verify field length limits
3. **Renewal/Date Validation**:
   - Try renewal with invalid date input (past date) and verify client-side block
   - Try renewal with date before current validity start and verify error
   - Try renewal with non-numeric days input and verify validation
4. **Certificate Chain Validation**:
   - Try creating end-entity with revoked intermediate as issuer and verify error
   - Try creating intermediate with revoked root as issuer and verify error
5. **SAN/Email Validation**:
   - Try creating server cert with invalid SAN format (bad DNS) and verify error
   - Try creating email cert without email and verify required-field error
   - Try creating server cert with duplicate SAN entries and verify handling
6. **Authorization Violations**:
   - Try direct URL to create cert page as `user` role and confirm 403/redirect
   - Try revoke endpoint as `user` and confirm 403
   - Try direct URL to org dashboard of different org as lower role (if multi-tenancy applies)
7. **Session/Auth Edge Cases**:
   - Try accessing protected route with invalid/expired token and confirm redirect to login
   - Try accessing route with no auth header and confirm login redirect
   - Log out mid-operation and confirm session is cleared

## Automated Test Coverage (Already Verified by pytest)

These aspects are **already tested** by the automated test suite and do **not** need manual verification:

- ✅ **Certificate Metadata Extraction**: Subject fields, extensions parsed from PEM correctly
- ✅ **Database Consistency**: issuer_cert_id chain integrity, serial number uniqueness, cert UUID uniqueness
- ✅ **Policy Enforcement Logic**: Locked fields, role_defaults applied, cert type routing
- ✅ **RBAC Route Authorization**: Admin/manager/user endpoint access control
- ✅ **CRL Generation**: Revoked cert entries, CRL number tracking, issuer validation
- ✅ **Certificate Chain Validation**: End-entity → intermediate → root chain integrity
- ✅ **Extension Persistence**: Extensions stored in normalized tables (SAN, basic_constraints, key_usage, EKU)
- ✅ **Revocation Idempotency**: Double-revoke returns correct status

Run `pytest tests/ -v` to verify these before manual testing.

---

## Exit Criteria

1. Every route-backed UI feature tested at least once.
2. Every role (`admin`, `manager`, `user`) permission boundary verified.
3. All create, renew, revoke, download, CRL, consistency, and health flows verified.
4. Extension metadata rendering verified in certificate popup (Phase 3, step 6).
5. Policy enforcement edge cases tested (Phase 2, steps 5/12/19).
6. Organization isolation confirmed (Phase 1, step 6).
7. CRL content verification completed (Phase 5, steps 9-10).
8. All negative/validation cases tested (Phase 8).
9. Any failures logged with exact step number, URL, role, and screenshot.
