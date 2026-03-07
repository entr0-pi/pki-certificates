# End-to-End Web App Test Plan (Step-by-Step)

Use this in order, and record each step as PASS/FAIL with screenshot + note.

## Phase 0: Authentication and Session

- [ ] Start app and open `http://localhost:<port>/auth/login`.
- [ ] Confirm unauthenticated access to `/` redirects to `/auth/login`.
- [ ] Try invalid API key and confirm login error message.
- [ ] Log in with `admin` API key.
- [ ] Confirm landing page shows role badge `admin`.
- [ ] Click `Logout` and confirm you return to login page.
- [ ] Log in again with `admin` for full functional run.

## Phase 1: Landing + Organization Management

- [ ] On `/`, verify organization cards load (or empty state with create CTA).
- [ ] If no org exists, create one from modal (`Organization Name` required).
- [ ] If org exists, create an additional org via `Create Organization` button.
- [ ] Organization Creation Details: try creating org with duplicate name and confirm error (should be UNIQUE in DB).
- [ ] Organization Creation Details: try creating org with very long name and confirm it's sanitized/truncated appropriately.
- [ ] Organization Creation Details: verify new org gets unique folder name (for example `org_<id>_<sanitized_name>`).
- [ ] Confirm new org appears with ID and created date in card.
- [ ] Organization Isolation: create 2+ orgs and create certs in each.
- [ ] Organization Isolation: verify org A's dashboard only shows org A's certs (no cross-org leakage).
- [ ] Organization Isolation: try accessing org B's cert popup from org A via direct URL and confirm 403/error.
- [ ] Open one org via `Manage`.
- [ ] Confirm dashboard header, stats, and certificate table render.
- [ ] Confirm `Create Certificate` button is visible for admin.
- [ ] Open `CRL Downloads` menu and verify both links exist (`Latest CRL`, `CRL Bundle`).
- [ ] Audit Trail (if UI displays audit logs): verify org creation is logged with timestamp and user identity.
- [ ] Audit Trail (if UI displays audit logs): verify cert operations appear in org-level audit log (if available).
- [ ] Click `Refresh` and confirm page reloads without errors.

## Phase 2: Unified Certificate Creation

- [ ] From org dashboard, open `Create Certificate`.
- [ ] In `Root CA` tab, confirm all compulsory fields show `*`.
- [ ] Confirm `Certificate Valid For` and `EC Curve` also show `*`.
- [ ] Submit with one required field empty and confirm browser blocks submission.
- [ ] Policy Enforcement - Root CA: verify locked fields (if policy enforces them) are disabled/read-only.
- [ ] Policy Enforcement - Root CA: try entering invalid country code (non-2-char) and confirm validation error.
- [ ] Policy Enforcement - Root CA: try entering invalid email format and confirm validation error.
- [ ] Policy Enforcement - Root CA: verify EC curve dropdown only shows policy-allowed curves.
- [ ] Policy Enforcement - Root CA: verify default validity matches policy if not overridden.
- [ ] Fill valid root data and create root cert.
- [ ] Confirm success response and return to org dashboard.
- [ ] Verify root cert appears in table with status `active`.
- [ ] Open root cert popup and verify subject fields, extensions, and validity.
- [ ] Back to `Create Certificate`, open `Intermediate CA` tab.
- [ ] Confirm required markers and locked-field behavior (policy lock applies for subject fields).
- [ ] Policy Enforcement - Intermediate CA: verify subject fields are locked/prefilled if policy requires them to match root, with all fields.
- [ ] Policy Enforcement - Intermediate CA: try creating without an active issuer and confirm error.
- [ ] Policy Enforcement - Intermediate CA: verify EC curve options match policy restrictions.
- [ ] Create an intermediate CA with valid values.
- [ ] Confirm success and presence in dashboard table.
- [ ] Open `End-Entity` tab.
- [ ] Check `Server` type default: SAN section visible, Email not required, OCSP toggle visible.
- [ ] Switch to `Email` type: SAN hidden, Email becomes required and `*` appears, OCSP toggle hidden.
- [ ] Switch to `Client` type: Email optional again and `*` removed, OCSP toggle hidden.
- [ ] Switch back to `Server` type: OCSP toggle reappears and is unchecked.
- [ ] Policy Enforcement - End-Entity: verify subject fields reflect locked/policy-enforced values.
- [ ] Policy Enforcement - End-Entity: try selecting root CA as issuer and confirm error (end-entity must use intermediate).
- [ ] Policy Enforcement - End-Entity: try selecting revoked intermediate as issuer and confirm error.
- [ ] Policy Enforcement - End-Entity: verify SAN validation (DNS names, IP format) on server cert.
- [ ] Policy Enforcement - End-Entity: verify email validation on email cert type.
- [ ] Create one `server` certificate with SAN entries (test multiple SAN types).
- [ ] Create one `client` certificate.
- [ ] Create one `email` certificate with required email.
- [ ] Create one `OCSP` certificate: select `Server` type, toggle `OCSP Responder`, verify SAN section is hidden.
- [ ] Verify OCSP cert creation succeeds with no SAN entries.
- [ ] Confirm OCSP cert shows in dashboard with type `ocsp` and active status.
- [ ] Verify toggling OCSP responder off restores SAN section visibility with default SAN row.
- [ ] Confirm all four cert types appear in dashboard with correct type and active status.

## Phase 3: Certificate Table, Filters, Popup, Downloads

- [ ] Use search box with part of cert name; verify row filtering.
- [ ] Filter by type `root`, `intermediate`, `server`, `client`, `email`, `ocsp`.
- [ ] Filter by status `active`.
- [ ] Filter by expiry windows and verify badges (`critical`, `warning`, `healthy`, `expired`).
- [ ] Open each cert `View Details` popup from row action.
- [ ] In popup, verify subject fields: CN, O, OU, C, ST, L, Email (if present).
- [ ] In popup, verify Basic Constraints: `is_ca` flag and `path_length` (if present).
- [ ] In popup, verify Key Usage flags render correctly.
- [ ] In popup, verify Extended Key Usage renders human-readable values.
- [ ] In popup, verify Subject Alternative Names list all DNS/IP entries with types for server certs.
- [ ] In popup, verify serial number format and uniqueness.
- [ ] In popup, verify Not Before / Not After dates display correctly.
- [ ] In popup, verify issuer certificate name and chain path.
- [ ] For a cert, download `PEM` and verify file downloads.
- [ ] For `client` or `email`, click `Download PKCS12` and confirm the password prompt modal opens before download.
- [ ] In the PKCS#12 password prompt, confirm a password value is displayed.
- [ ] In the PKCS#12 password prompt, use the copy action and confirm copy feedback is shown.
- [ ] In the PKCS#12 password prompt, click `Download P12` and verify the `.p12` file downloads.
- [ ] For a PKCS#12-enabled cert, close and reopen the prompt to confirm it can be fetched repeatedly without UI errors.
- [ ] For any cert, download `Chain` and verify file downloads.
- [ ] For `server`, download `Private Key` and verify file downloads.

## Phase 4: Renewal Flow

- [ ] From an active cert action menu, click `Renew`.
- [ ] On renew page, verify original cert details are shown (read-only).
- [ ] Confirm only renewal fields are editable (`New Certificate Name`, validity controls).
- [ ] Renewal for End-Entity: renew using `Days from now` (for example 365 days).
- [ ] Renewal for End-Entity: confirm success and redirected/returned view.
- [ ] Renewal for End-Entity: verify new cert exists with incremented serial number.
- [ ] Renewal for End-Entity: verify old cert is auto-revoked with reason `superseded`.
- [ ] Renewal for End-Entity: verify new cert shows in dashboard as `active` while old shows as `revoked`.
- [ ] Renewal for Intermediate CA: renew an intermediate CA using `Days from now`.
- [ ] Renewal for Intermediate CA: verify old intermediate is revoked and appears in CRL.
- [ ] Renewal for Intermediate CA: verify end-entity certs issued by old intermediate still validate through issuer chain behavior.
- [ ] Date-mode Renewal: repeat renewal for another cert using `Specific date`.
- [ ] Date-mode Renewal: verify renewal succeeds with correct validity date.
- [ ] Date-mode Renewal: verify new cert's `Not After` matches the selected date.
- [ ] Renewal Edge Cases: try renewing an already-revoked cert and confirm error.
- [ ] Renewal Edge Cases: try renewing with invalid certificate name and confirm validation.
- [ ] Renewal Edge Cases: verify renewed cert has a new UUID artifact.

## Phase 5: Revocation + CRL

- [ ] On org dashboard, choose an active cert and click `Revoke`.
- [ ] In modal, test reason selection list (all options available).
- [ ] Submit revocation with `keyCompromise`.
- [ ] Confirm cert status becomes `revoked` in dashboard.
- [ ] Revocation Details: verify revocation reason is recorded in database/audit logs.
- [ ] Revocation Details: try revoking the same cert again and confirm error or idempotent behavior.
- [ ] Revocation Details: verify revoked cert no longer appears in issuer dropdown for new end-entity certs.
- [ ] Revoke another active cert with a different reason (for example `superseded`).
- [ ] Download org `Latest CRL` and confirm file is returned (PEM format).
- [ ] Download org `CRL Bundle` and confirm archive is returned (ZIP with multiple CRLs).
- [ ] CRL Content Verification: open downloaded CRL and verify revoked cert serial numbers appear.
- [ ] CRL Content Verification: verify CRL validity dates (`thisUpdate`, `nextUpdate`).
- [ ] CRL Content Verification: verify CRL issuer matches expected CA.
- [ ] CRL Content Verification: verify CRL number increments on subsequent revocations.
- [ ] CRL Content Verification: confirm both revoked certs appear in CRL.
- [ ] Issuer-Specific CRL: open issuer-specific CRL URL if available.
- [ ] Issuer-Specific CRL: verify response contains only revocations by that issuer.
- [ ] Issuer-Specific CRL: verify revoked cert serials match database records.

## Phase 6: Health + Consistency + Toolbox

- [ ] On landing or org dashboard, run `Consistency Check`.
- [ ] Confirm modal opens and API response renders test list.
- [ ] If success, verify all checks show `OK`.
- [ ] If failures, verify issues list appears with level and message.
- [ ] Open `/health` as admin and verify healthy JSON/text response.
- [ ] Open `/healthz` and verify liveness response.
- [ ] Open `/toolbox` and verify page loads (admin only).

## Phase 7: RBAC Validation (Critical)

Log out between roles and re-login each time.

- [ ] Login as `manager`.
- [ ] Confirm manager can access `/`, org dashboard, unified create page.
- [ ] Confirm manager can create end-entity certs.
- [ ] Confirm manager cannot create root/intermediate (UI warning or blocked action).
- [ ] Confirm manager can renew certs.
- [ ] Confirm manager cannot revoke certs.
- [ ] Confirm manager can download certs (PEM/chain/PKCS12 where applicable).
- [ ] Confirm manager can open the PKCS#12 password prompt for eligible certificates.
- [ ] Confirm manager cannot download plain private key.
- [ ] Confirm manager can run consistency check.
- [ ] Confirm manager cannot access `/toolbox` (403).
- [ ] Login as `user`.
- [ ] Confirm user can access landing and org dashboard.
- [ ] Confirm user cannot access unified create page.
- [ ] Confirm user can open certificate popup.
- [ ] Confirm user cannot download certs/private key.
- [ ] Confirm user cannot open the PKCS#12 password prompt.
- [ ] Confirm user cannot renew/revoke.
- [ ] Confirm user cannot run consistency check.

## Phase 8: Negative/Validation Cases

- [ ] Certificate Name Validation: try creating cert with duplicate name in same org and verify error (if enforced).
- [ ] Certificate Name Validation: try creating cert with very long name and verify sanitization (only alphanumeric, `-`, `_`).
- [ ] Certificate Name Validation: try creating cert with special chars (`!@#$%`) and verify they're stripped.
- [ ] Subject Field Validation: try invalid country code (3+ chars or empty) and verify validation error.
- [ ] Subject Field Validation: try invalid email format and verify validation error.
- [ ] Subject Field Validation: try very long organizational unit and verify field length limits.
- [ ] Renewal/Date Validation: try renewal with invalid date input (past date) and verify client-side block.
- [ ] Renewal/Date Validation: try renewal with date before current validity start and verify error.
- [ ] Renewal/Date Validation: try renewal with non-numeric days input and verify validation.
- [ ] Certificate Chain Validation: try creating end-entity with revoked intermediate as issuer and verify error.
- [ ] Certificate Chain Validation: try creating intermediate with revoked root as issuer and verify error.
- [ ] SAN/Email Validation: try creating server cert with invalid SAN format and verify error.
- [ ] SAN/Email Validation: try creating email cert without email and verify required-field error.
- [ ] SAN/Email Validation: try creating server cert with duplicate SAN entries and verify handling.
- [ ] Authorization Violations: try direct URL to create cert page as `user` role and confirm 403/redirect.
- [ ] Authorization Violations: try revoke endpoint as `user` and confirm 403.
- [ ] Authorization Violations: try direct URL to org dashboard of different org as lower role (if multi-tenancy applies).
- [ ] Session/Auth Edge Cases: try accessing protected route with invalid/expired token and confirm redirect to login.
- [ ] Session/Auth Edge Cases: try accessing route with no auth header and confirm login redirect.
- [ ] Session/Auth Edge Cases: log out mid-operation and confirm session is cleared.
- [ ] PKCS#12 Prompt Negative Case: try opening the PKCS#12 password prompt for a non-client/non-email certificate and confirm the UI does not offer it.
- [ ] PKCS#12 Prompt Negative Case: simulate or trigger a password-fetch failure and confirm the UI shows an error instead of a broken modal.

## Automated Test Coverage (Already Verified by pytest)

These aspects are already tested by the automated test suite and do not need manual verification:

- [ ] Certificate Metadata Extraction: subject fields and extensions parsed from PEM correctly.
- [ ] Database Consistency: `issuer_cert_id` chain integrity, serial number uniqueness, cert UUID uniqueness.
- [ ] Policy Enforcement Logic: locked fields, `role_defaults` applied, cert type routing.
- [ ] RBAC Route Authorization: admin/manager/user endpoint access control.
- [ ] CRL Generation: revoked cert entries, CRL number tracking, issuer validation.
- [ ] Certificate Chain Validation: end-entity -> intermediate -> root chain integrity.
- [ ] Extension Persistence: extensions stored in normalized tables (SAN, basic_constraints, key_usage, EKU).
- [ ] Revocation Idempotency: double-revoke returns correct status.
- [ ] PKCS#12 Bundle Generation: encrypted `.p12` bundle and password file exist for eligible certificates.

Run `pytest tests/ -v` to verify these before manual testing.

---

## Exit Criteria

- [ ] Every route-backed UI feature tested at least once.
- [ ] Every role (`admin`, `manager`, `user`) permission boundary verified.
- [ ] All create, renew, revoke, download, CRL, consistency, and health flows verified.
- [ ] Extension metadata rendering verified in certificate popup (Phase 3).
- [ ] Policy enforcement edge cases tested (Phase 2).
- [ ] Organization isolation confirmed (Phase 1).
- [ ] CRL content verification completed (Phase 5).
- [ ] All negative/validation cases tested (Phase 8).
- [ ] PKCS#12 password prompt flow verified for eligible roles and certificate types.
- [ ] Any failures logged with exact phase item, URL, role, and screenshot.
