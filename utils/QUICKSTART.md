# Environment Setup Quickstart

The `generate_env.py` script creates and configures your `.env` file from `.env.example`, auto-generating cryptographic secrets and applying environment-specific defaults.

## Quick Start

### Development (Recommended for Local Setup)

```bash
python utils/generate_env.py --env dev
```

**What it does:**
- Auto-generates all secrets (encryption keys, API keys, JWT secret)
- Sets localhost defaults: `PKI_HOST=127.0.0.1`, `PKI_BASE_URL=http://localhost:8000`
- Enables debug logging: `PKI_LOG_LEVEL=DEBUG`
- Disables HTTPS requirement: `PKI_COOKIE_SECURE=false`
- Uses log-only notifications (no SMTP/webhook)
- **No interactive prompts** — runs in CI/automation-friendly mode

### Production

```bash
python utils/generate_env.py --env production
```

**What happens:**
- Auto-generates all secrets
- Prompts for public URL: `PKI_BASE_URL` (e.g., `https://pki.example.com`)
- Prompts for notification method: `log` / `email` / `webhook`
- If `email`: collects SMTP server details
- If `webhook`: collects webhook endpoint
- Sets production security defaults:
  - `PKI_HOST=0.0.0.0` (listen on all interfaces)
  - `PKI_COOKIE_SECURE=true` (HTTPS only)
  - `PKI_COOKIE_SAMESITE=strict` (strongest CSRF protection)
  - `PKI_LOG_LEVEL=INFO` (minimal verbosity)

## Available Flags

| Flag | Purpose |
|---|---|
| `--env {dev,production}` | Select profile without interactive menu |
| `--dry-run` | Print changes and summary table; don't write file |
| `--force` | Skip confirmation prompt (still creates backup) |
| `--example PATH` | Use alternate `.env.example` file (default: `.env.example`) |
| `--output PATH` | Write to alternate location (default: `.env`) |

## Use Cases

### First-Time Setup
```bash
# One command for local dev
python utils/generate_env.py --env dev
```

### Preview Changes Before Writing
```bash
# See what would change without modifying .env
python utils/generate_env.py --env production --dry-run
```

### Automated CI/Deployment
```bash
# Non-interactive, suitable for Docker/CI pipelines
python utils/generate_env.py --env dev --force
```

### Regenerate Secrets (Careful!)
```bash
# Force overwrite existing .env (backs up to .env.bak first)
python utils/generate_env.py --env dev --force
```

## Output: Summary Table

After running, you'll see a table showing what was changed:

```
+----------------------------+------------------+----------------------------+
| KEY                        | SOURCE           | VALUE PREVIEW              |
+----------------------------+------------------+----------------------------+
| PKI_ENCRYPTION_KEY         | generated        | dX9kLm***                  |
| PKI_BASE_URL               | interactive      | https://pki.example.com    |
| PKI_HOST                   | profile_default  | 0.0.0.0                    |
| PKI_LOG_LEVEL              | kept             | INFO                       |
+----------------------------+------------------+----------------------------+
```

**Source** explains where each value came from:
- `generated` — cryptographic secret auto-created
- `interactive` — you entered it in a prompt
- `profile_default` — set by the selected environment profile
- `kept` — preserved from your existing `.env`
- `example_default` — taken as-is from `.env.example`

Secrets (like `PKI_ENCRYPTION_KEY`) show only first 6 chars + `***` for security.

## What Gets Generated

These six keys are auto-generated with strong random values:

- `PKI_ENCRYPTION_KEY` — 32-byte AES-256 key (base64-encoded)
- `PKI_ENCRYPTION_SALT` — 32-byte PBKDF2 salt (base64-encoded)
- `PKI_API_KEY_ADMIN` — Admin API authentication token
- `PKI_API_KEY_MANAGER` — Manager API authentication token
- `PKI_API_KEY_USER` — User API authentication token
- `PKI_JWT_SECRET` — Session token signing secret

**Caution:** Changing `PKI_ENCRYPTION_SALT` makes all encrypted files inaccessible. Keep it safe.

## Preserving Existing Secrets

If you re-run the script with an existing `.env`:
- Non-placeholder values are **kept** unchanged
- Only placeholder values (like `change-this-admin-api-key`) are regenerated
- A backup `.env.bak` is created before any overwrite

This means you can safely re-run the script to fill in missing values without destroying your secrets.

## Interactive Mode Details

### Development Profile
Runs entirely non-interactive. Suitable for automation.

### Production Profile
Prompts for these fields:

1. **PKI_BASE_URL** — Your public certificate authority URL
   - e.g., `https://pki.example.com` or `https://ca.yourdomain.com`
   - ⚠️ Must be externally reachable; baked into issued certificates
   - Warns if set to `localhost` (not safe for production)

2. **NOTIFY_METHOD** — How to send expiration alerts
   - `log` — write to application logs only
   - `email` — send SMTP emails
   - `webhook` — POST to a webhook endpoint

3. **SMTP Details** (if `NOTIFY_METHOD=email`)
   - SMTP_HOST
   - SMTP_PORT (default: 587)
   - SMTP_USER
   - SMTP_PASS
   - EMAIL_TO (comma-separated recipients)

4. **Webhook URL** (if `NOTIFY_METHOD=webhook`)
   - Endpoint that receives certificate expiration alerts

5. **Optional Fields** (press Enter to skip)
   - PKI_COOKIE_DOMAIN — for session sharing across subdomains
   - PKI_DATA_DIR — custom storage path (default: `./data`)
   - PKI_DB_PATH — custom SQLite path (default: `./database/pki.db`)

## Validation & Warnings

The script checks for common issues and prints warnings (non-fatal):

```
WARN: PKI_BASE_URL should not be localhost in production
WARN: NOTIFY_METHOD=email requires SMTP_HOST
```

Review these before deploying. Warnings don't prevent `.env` from being written.

## Troubleshooting

### "Refusing to overwrite existing file"
Your `.env` already exists. Choose one:
- Edit it manually
- Use `--force` to overwrite (backs up to `.env.bak`)
- Use `--dry-run` to preview changes first

### "Example file not found"
The script expects `.env.example` in the repo root. Check that it exists or specify `--example path/to/.env.example`.

### "EOFError: EOF when reading a line"
Running in non-interactive mode (piped input) but the script needs more input than you provided.
- Use `--env dev` (non-interactive) for automation
- Or provide more input lines via pipe/heredoc for production mode

### Secrets look wrong or empty
Check the summary table `SOURCE` column. If a secret shows `example_default` or `kept`, re-run with `--force` to regenerate it:
```bash
python utils/generate_env.py --env dev --force
```

## Next Steps

1. **Run the setup:**
   ```bash
   python utils/generate_env.py --env dev
   ```

2. **Verify `.env` was created:**
   ```bash
   ls -la .env
   ```

3. **Start the application** (see main README for instructions)

For more details on PKI configuration, see `docs/SECURITY.md`.
