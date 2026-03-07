#!/usr/bin/env python3
"""
Migration script: v1 → v2 (adds 'ocsp' cert type support)

SQLite does not support ALTER TABLE to modify CHECK constraints.
This script recreates the `certificates` table with the updated CHECK constraint.

Usage:
    python scripts/migrate_v1_to_v2.py [--db-path PATH]

Environment:
    PKI_DB_PATH: Default database path (used if --db-path not provided)
"""

import argparse
import os
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(
        description="Migrate PKI database from v1 to v2 (add OCSP cert type)"
    )
    parser.add_argument(
        "--db-path",
        default=os.getenv("PKI_DB_PATH", "pki.db"),
        help="Path to SQLite database (default: $PKI_DB_PATH or 'pki.db')"
    )
    args = parser.parse_args()

    db_path = Path(args.db_path)

    if not db_path.exists():
        print(f"ERROR: Database not found: {db_path}")
        sys.exit(1)

    # Create backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = db_path.parent / f"{db_path.name}.backup.{timestamp}"
    print(f"Creating backup: {backup_path}")
    shutil.copy2(db_path, backup_path)

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Verify current schema version
        cursor.execute("SELECT version FROM schema_version LIMIT 1")
        row = cursor.fetchone()
        if not row:
            print("ERROR: schema_version table is empty")
            conn.close()
            sys.exit(1)

        current_version = row[0]
        if current_version != 1:
            print(f"ERROR: Current schema version is {current_version}, expected 1")
            print(f"Migration should only be run on v1 databases")
            conn.close()
            sys.exit(1)

        print(f"Current schema version: {current_version}")

        # Begin transaction
        cursor.execute("BEGIN TRANSACTION")

        # Step 1: Create certificates_new with updated CHECK constraint
        print("Creating certificates_new table...")
        cursor.execute("""
            CREATE TABLE certificates_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_uuid VARCHAR(36) UNIQUE NOT NULL,
                organization_id INTEGER NOT NULL,
                cert_name VARCHAR(255) NOT NULL,
                cert_type VARCHAR(32) NOT NULL,
                issuer_cert_id INTEGER,
                subject_c VARCHAR(2),
                subject_st VARCHAR(128),
                subject_l VARCHAR(128),
                subject_o VARCHAR(128),
                subject_ou VARCHAR(128),
                subject_cn VARCHAR(255),
                subject_email VARCHAR(255),
                serial_number VARCHAR(256) UNIQUE NOT NULL,
                not_before TIMESTAMP,
                not_after TIMESTAMP,
                key_algorithm VARCHAR(32),
                key_size INTEGER,
                ec_curve VARCHAR(32),
                signature_hash VARCHAR(32),
                cert_path TEXT,
                key_path TEXT,
                csr_path TEXT,
                pwd_path TEXT,
                status VARCHAR(16) DEFAULT 'active',
                revoked_at TIMESTAMP,
                revocation_reason VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY (issuer_cert_id) REFERENCES certificates_new(id) ON DELETE RESTRICT,

                CONSTRAINT cert_type_check CHECK (cert_type IN ('root', 'intermediate', 'server', 'client', 'email', 'ocsp')),
                CONSTRAINT status_check CHECK (status IN ('active', 'revoked', 'expired'))
            )
        """)

        # Step 2: Copy all data from certificates to certificates_new
        print("Copying certificate data...")
        cursor.execute("""
            INSERT INTO certificates_new
            SELECT * FROM certificates
        """)

        # Step 3: Drop old table
        print("Dropping old certificates table...")
        cursor.execute("DROP TABLE certificates")

        # Step 4: Rename new table
        print("Renaming certificates_new to certificates...")
        cursor.execute("ALTER TABLE certificates_new RENAME TO certificates")

        # Step 5: Update schema version
        print("Updating schema version to 2...")
        cursor.execute("UPDATE schema_version SET version = 2")

        # Commit transaction
        conn.commit()
        conn.close()

        print("✅ Migration completed successfully!")
        print(f"Backup saved to: {backup_path}")

    except Exception as e:
        print(f"ERROR during migration: {e}")
        import traceback
        traceback.print_exc()
        print(f"Your original database has been backed up to: {backup_path}")
        sys.exit(1)

if __name__ == "__main__":
    main()
