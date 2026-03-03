# PKI Cron Jobs

Recommended scheduled tasks for PKI operations.

## Expiration Notifications

Run daily at 08:00 to notify about certificates expiring in the next 30 days.

```bash
0 8 * * * cd /path/to/pki && python scripts/notify_expiring.py --days 30
```

Dry-run check:

```bash
python scripts/notify_expiring.py --dry-run
```

## Consistency Checker

Run periodic DB/filesystem consistency validation and alert on inconsistencies.

Recommended schedule (every hour, strict mode):

```bash
0 * * * * cd /path/to/pki && python scripts/check_consistency.py --strict >> /var/log/pki-consistency.log 2>&1
```

Recommended schedule with report file (daily at 02:30):

```bash
30 2 * * * cd /path/to/pki && python scripts/check_consistency.py --strict --report-file /var/log/pki-consistency-report.txt >> /var/log/pki-consistency.log 2>&1
```

Manual runs:

```bash
python scripts/check_consistency.py
python scripts/check_consistency.py --strict
python scripts/check_consistency.py --report-file ./consistency-report.txt
```

Behavior and exit codes:

- `0`: checks passed, or inconsistencies found without `--strict`
- `1`: inconsistencies found with `--strict`
- `2`: fatal error while running checks

Notes:

- The checker also tracks file hash integrity across runs using `PKI_DATA_DIR/.pki_file_hashes.json`.
- First run baselines hashes; subsequent runs flag unexpected changes.
- CRL artifacts and the manifest file itself are excluded from hash mismatch checks.

## Environment Variables

Notification method:

```bash
export NOTIFY_METHOD="log"       # log | email | webhook
```

Email mode:

```bash
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USER="pki@example.com"
export SMTP_PASS="password"
export EMAIL_TO="admin@example.com,ops@example.com"
```

Webhook mode:

```bash
export WEBHOOK_URL="https://hooks.slack.com/services/..."
```

Consistency checker related:

```bash
export PKI_DATA_DIR="/path/to/pki/data"            # optional override for data root
export PKI_DB_PATH="/path/to/pki/database/pki.db"  # if your deployment does not use default DB path
export PKI_ENFORCE_CA_EMPTY_PWD_PATH="true"        # optional policy validation toggle
```
