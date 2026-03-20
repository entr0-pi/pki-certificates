# Utils

## `generate_env.py` — Environment Setup

Creates and configures your `.env` file from `.env.example`, auto-generating cryptographic secrets.

```bash
# Local development (non-interactive)
python utils/generate_env.py --env dev

# Production (interactive prompts for URL, notifications)
python utils/generate_env.py --env production
```

**Flags:**

| Flag | Purpose |
|---|---|
| `--env {dev,production}` | Select profile |
| `--dry-run` | Preview changes without writing |
| `--force` | Skip confirmation (creates `.env.bak` backup) |
| `--example PATH` | Alternate `.env.example` path |
| `--output PATH` | Alternate output path |

**Auto-generated secrets:** `PKI_ENCRYPTION_KEY`, `PKI_ENCRYPTION_SALT`, `PKI_API_KEY_ADMIN`, `PKI_API_KEY_MANAGER`, `PKI_API_KEY_USER`, `PKI_JWT_SECRET`

> **Caution:** Changing `PKI_ENCRYPTION_KEY` or `PKI_ENCRYPTION_SALT` makes all existing encrypted files inaccessible unless you first re-encrypt them with `encryption_manager.py rotate` (see below).

Re-running is safe: existing non-placeholder values are preserved; a `.env.bak` backup is created before any overwrite.

---

## `encryption_manager.py` — Decrypt & Rotate PKI Artifacts

Manages encrypted `.enc` artifacts (AES-256-GCM, PBKDF2 key derivation). Three subcommands: `prepare`, `decrypt`, and `rotate`.

**Key rotation workflow (end-to-end):**
```bash
# 1. Create .env.new with new key/salt (all other vars preserved)
python utils/encryption_manager.py prepare --env .env --output .env.new

# 2. Dry-run to confirm scope
python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/ --dry-run

# 3. Rotate artifacts (optionally add --backup-dir /tmp/backup/)
python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/

# 4. Promote new credentials and restart the app
cp .env.new .env
```

### prepare

Copies an existing `.env` to a new file and replaces `PKI_ENCRYPTION_KEY` and `PKI_ENCRYPTION_SALT` with freshly generated values. All other variables are preserved unchanged. Use this before `rotate`.

```bash
python utils/encryption_manager.py prepare --env .env --output .env.new

# Overwrite if .env.new already exists
python utils/encryption_manager.py prepare --env .env --output .env.new --force
```

**Flags:** `--env/-e` (source), `--output/-o` (destination), `--force`

### decrypt

```bash
# Single file to stdout
python utils/encryption_manager.py decrypt --env .env -i data/org_1_acme/intermediates/ca/private/ca.key.enc

# Single file to output file
python utils/encryption_manager.py decrypt --env .env -i ca.key.enc -o ca.key

# Entire data directory tree (mirrors structure, strips .enc suffix)
python utils/encryption_manager.py decrypt --env .env -i data/ -o /tmp/pki_plain/

# Dry-run / explicit credentials
python utils/encryption_manager.py decrypt --env .env -i data/ --dry-run
python utils/encryption_manager.py decrypt --key <KEY> --salt <SALT> -i data/ -o /tmp/pki_plain/
```

**Flags:** `--env/-e`, `--key/-k`, `--salt/-s`, `--input/-i`, `--output/-o`, `--dry-run`

### rotate

Re-encrypts all `.enc` files under a directory with a new key/salt. Each file is updated atomically (temp file + rename). Verifies the old key against the first file before proceeding.

Use `prepare` to create `.env.new` before rotating (copies all vars, replaces only the two encryption vars):

```bash
python utils/encryption_manager.py prepare --env .env --output .env.new
```

```bash
# In-place rotation using two .env files
python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/

# Write rotated files to a separate directory (originals untouched)
python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/ -o /tmp/rotated/

# Backup originals before in-place overwrite
python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/ --backup-dir /tmp/backup/

# Explicit credentials / dry-run
python utils/encryption_manager.py rotate --old-key K1 --old-salt S1 --new-key K2 --new-salt S2 -i data/
python utils/encryption_manager.py rotate --old-env .env --new-env .env.new -i data/ --dry-run
```

**Flags:** `--old-env`, `--old-key`, `--old-salt`, `--new-env`, `--new-key`, `--new-salt`, `--input/-i`, `--output/-o`, `--backup-dir`, `--dry-run`

> **Caution:** After a successful in-place rotation, replace `.env` with `.env.new` (`cp .env.new .env`) before restarting the application. The app will fail to decrypt artifacts if `.env` still contains the old key/salt.
