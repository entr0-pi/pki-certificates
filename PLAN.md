# Root Certificate User-Provided Password Plan (No Implementation)

## Objective
Introduce a second, user-provided password for **root key usage** while keeping encryption at rest unchanged.

When root private key access is required, use:

- `effective_root_key_password = HMAC(password_from_filesystem, password_provided_by_user)`

Constraints:
- Keep existing password-at-rest storage unchanged.
- Keep non-root certificate logic unchanged.
- Minimize changes.

---

## Scope

### In scope
- Identify where root password is currently used in backend and frontend.
- Define a minimal flow for collecting a user-provided password only when root key use is required.
- Define behavior for:
  - creation of intermediates (signed by root),
  - renewal paths that require root signing,
  - revocation/CRL generation when root signs.

### Out of scope
- No code changes.
- No schema/storage migration.
- No change to encryption-at-rest mechanism.

---

## Current Usage Inventory

### Backend (where root password is used today)
1. **Root CA key/password lifecycle**
   - `backend/root_ca_create_crypto.py`
2. **Intermediate creation signed by root**
   - `backend/intermediate_ca_create_crypto.py`
3. **End-entity creation when issuer is root**
   - `backend/end_entity_create_crypto.py`
4. **Revocation / CRL signing with issuer key**
   - `backend/revoke_cert_crypto.py`
   - `backend/app.py` (`_trigger_crl_regeneration`)
5. **Private key loading/validation paths**
   - `backend/cert_crypto.py`
   - `backend/root_ca_validate.py`

### Frontend (where user input must be added/conditioned)
1. **Create certificate flow**
   - `frontend/templates/create_certificate.html`
2. **Renew certificate flow**
   - `frontend/templates/renew_certificate.html`
3. **Revoke flow (modal)**
   - `frontend/templates/organization_dashboard.html`

---

## Target Functional Behavior

1. **Root password from filesystem remains required** (as today).
2. **Additional user password is required only when root key is used**.
3. **Derived password is used only in-memory for root key operations**.
4. **Other certificate types/issuers remain unchanged**.
5. **No persistence of user-provided password**.

---

## Minimal-Change Plan

### Phase 1 — Design alignment
- Confirm exact derivation contract: HMAC input ordering, encoding, and output format.
- Confirm operations that require root key use:
  - intermediate issuance by root,
  - renewals whose issuer is root,
  - revocation/CRL regeneration where issuer is root.

### Phase 2 — Request/UX contract
- Add one request field name for UI/backend contract (e.g., `root_user_password`).
- Make it conditional:
  - required only when issuer is root,
  - absent/ignored for non-root issuer paths.
- Add user-facing copy that clarifies: password is used for unlock operation and not stored.

### Phase 3 — Backend flow definition
- For root-key-required operations:
  - read current filesystem root password,
  - combine with user password via HMAC,
  - use derived value to unlock root private key.
- For non-root operations:
  - keep current behavior exactly as-is.
- Define failure behavior:
  - missing/invalid user password on root-required operations returns validation error,
  - no fallback that bypasses user password.

### Phase 4 — Frontend flow definition
- Create flow:
  - show field when issuer is root (especially intermediate issuance).
- Renew flow:
  - show field when renewal will use root issuer.
- Revoke flow:
  - show field when CRL signer is root.

### Phase 5 — Validation and rollout checks
- Verify no encryption-at-rest changes.
- Verify non-root paths unchanged.
- Verify root-required operations now require user-provided password.
- Roll out in smallest increments to reduce risk.

---

## Acceptance Criteria

1. A complete inventory exists for backend and frontend root-password touchpoints.
2. Root key operations are explicitly identified and gated by user-provided password.
3. Derived-password behavior is defined without changing storage format.
4. Non-root certificate behavior is explicitly unchanged.
5. Plan remains implementation-agnostic and minimal.

---

## Risks and Mitigations (Planning Level)

- **Risk:** Missing a root-key usage path.
  - **Mitigation:** Validate all create/renew/revoke flows against the inventory above.
- **Risk:** UX confusion on when password is required.
  - **Mitigation:** Conditional UI with clear helper text.
- **Risk:** Accidental persistence/logging of user password.
  - **Mitigation:** Define explicit non-persistence and non-logging requirement.

---

## Deliverable
This document is the deliverable: a plan-only specification for introducing user-provided root unlock password behavior with minimal change and no implementation in this step.
