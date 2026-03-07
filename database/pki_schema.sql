-- PKI Database Schema
-- SQLite database for managing PKI certificate information
-- Generated from DB_SCHEMA.md

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- 1. Organizations Table
CREATE TABLE organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_dir VARCHAR(255) NOT NULL UNIQUE,  -- e.g., "orgA"
    name VARCHAR(255) NOT NULL UNIQUE,     -- Organization display name (must be unique)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Certificates Table
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_uuid VARCHAR(36) NOT NULL UNIQUE,
    organization_id INTEGER NOT NULL,
    cert_name VARCHAR(255),  -- Now NULLABLE: optional display name (UUID used for folder structure)
    cert_type VARCHAR(20) NOT NULL,  -- 'root', 'intermediate', 'server', 'client', 'email'

    -- Issuer relationship (NULL for self-signed root CAs)
    issuer_cert_id INTEGER,  -- Foreign key to parent certificate

    -- Subject Distinguished Name
    subject_country VARCHAR(2),          -- C
    subject_state VARCHAR(128),          -- ST
    subject_locality VARCHAR(128),       -- L
    subject_organization VARCHAR(128),   -- O
    subject_org_unit VARCHAR(128),       -- OU
    subject_common_name VARCHAR(255) NOT NULL,  -- CN
    subject_email VARCHAR(255),

    -- Certificate details
    serial_number VARCHAR(64) UNIQUE NOT NULL,  -- Hex format
    not_before TIMESTAMP NOT NULL,
    not_after TIMESTAMP NOT NULL,

    -- Key information
    key_algorithm VARCHAR(20) NOT NULL,  -- 'EC' or 'RSA'
    key_size INTEGER,                    -- For RSA: 2048, 4096, etc.
    ec_curve VARCHAR(50),                -- For EC: 'secp256k1', 'secp384r1', 'secp521r1'
    signature_hash VARCHAR(20),          -- 'SHA256', 'SHA384', 'SHA512'

    -- File paths (relative to org_dir)
    cert_path VARCHAR(512) NOT NULL,
    key_path VARCHAR(512) NOT NULL,
    csr_path VARCHAR(512) NOT NULL,
    pwd_path VARCHAR(512) NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'active',  -- 'active', 'revoked', 'expired'
    revoked_at TIMESTAMP,
    revocation_reason VARCHAR(50),  -- 'keyCompromise', 'superseded', 'cessationOfOperation', etc.

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (issuer_cert_id) REFERENCES certificates(id) ON DELETE RESTRICT,

    CONSTRAINT cert_type_check CHECK (cert_type IN ('root', 'intermediate', 'server', 'client', 'email', 'ocsp')),
    CONSTRAINT status_check CHECK (status IN ('active', 'revoked', 'expired'))
    -- REMOVED: UNIQUE (organization_id, cert_name, cert_type)
    -- cert_uuid provides uniqueness; UUID now used for intermediate folder naming
);

-- 3. Subject Alternative Names (SAN) Table
CREATE TABLE subject_alternative_names (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL,
    san_type VARCHAR(20) NOT NULL,  -- 'DNS', 'EMAIL', 'IP', 'URI'
    san_value VARCHAR(255) NOT NULL,

    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
    CONSTRAINT san_type_check CHECK (san_type IN ('DNS', 'EMAIL', 'IP', 'URI'))
);

-- 4. Certificate Extensions Table
CREATE TABLE certificate_extensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL,
    extension_oid VARCHAR(64) NOT NULL,  -- e.g., '2.5.29.19' for BasicConstraints
    extension_name VARCHAR(100) NOT NULL,  -- 'BasicConstraints', 'KeyUsage', etc.
    is_critical BOOLEAN NOT NULL DEFAULT 0,
    extension_value TEXT NOT NULL,  -- JSON or string representation

    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
);

-- 5. BasicConstraints Table
CREATE TABLE basic_constraints (
    certificate_id INTEGER PRIMARY KEY,
    is_ca BOOLEAN NOT NULL,
    path_length INTEGER,  -- NULL means unlimited (for root CAs)

    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
);

-- 6. KeyUsage Table
CREATE TABLE key_usage (
    certificate_id INTEGER PRIMARY KEY,
    is_critical BOOLEAN DEFAULT 1,
    digital_signature BOOLEAN DEFAULT 0,
    content_commitment BOOLEAN DEFAULT 0,  -- non_repudiation
    key_encipherment BOOLEAN DEFAULT 0,
    data_encipherment BOOLEAN DEFAULT 0,
    key_agreement BOOLEAN DEFAULT 0,
    key_cert_sign BOOLEAN DEFAULT 0,
    crl_sign BOOLEAN DEFAULT 0,
    encipher_only BOOLEAN DEFAULT 0,
    decipher_only BOOLEAN DEFAULT 0,

    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE
);

-- 7. ExtendedKeyUsage Table
CREATE TABLE extended_key_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL,
    eku_oid VARCHAR(64) NOT NULL,
    eku_name VARCHAR(50) NOT NULL,  -- 'serverAuth', 'clientAuth', 'emailProtection', etc.

    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
    CONSTRAINT eku_name_check CHECK (eku_name IN (
        'serverAuth', 'clientAuth', 'emailProtection',
        'codeSigning', 'timeStamping', 'ocspSigning'
    ))
);

-- ============================================================================
-- CERTIFICATE REVOCATION TABLES
-- ============================================================================

-- 8. Certificate Revocation Lists (CRL) Table
CREATE TABLE crls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issuer_cert_id INTEGER NOT NULL,  -- CA that issued this CRL
    crl_number INTEGER NOT NULL,
    this_update TIMESTAMP NOT NULL,
    next_update TIMESTAMP NOT NULL,
    crl_path VARCHAR(512),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (issuer_cert_id) REFERENCES certificates(id) ON DELETE CASCADE,
    UNIQUE (issuer_cert_id, crl_number)
);

-- 9. Revoked Certificates Table
CREATE TABLE revoked_certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    crl_id INTEGER NOT NULL,
    certificate_id INTEGER NOT NULL,
    revocation_date TIMESTAMP NOT NULL,
    revocation_reason VARCHAR(50),

    FOREIGN KEY (crl_id) REFERENCES crls(id) ON DELETE CASCADE,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE,
    UNIQUE (crl_id, certificate_id)
);

-- ============================================================================
-- AUDIT TABLE
-- ============================================================================

-- 10. Certificate Audit Log Table
CREATE TABLE certificate_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER,
    operation VARCHAR(50) NOT NULL,  -- 'created', 'revoked', 'renewed', 'exported'
    operation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_name VARCHAR(100),
    details TEXT,  -- JSON with additional context

    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL
);

-- ============================================================================
-- PERFORMANCE INDEXES
-- ============================================================================

-- Certificate lookups
CREATE INDEX idx_certs_org ON certificates(organization_id);
CREATE INDEX idx_certs_issuer ON certificates(issuer_cert_id);
CREATE INDEX idx_certs_type ON certificates(cert_type);
CREATE INDEX idx_certs_status ON certificates(status);
CREATE INDEX idx_certs_not_after ON certificates(not_after);
CREATE INDEX idx_certs_serial ON certificates(serial_number);

-- Extension lookups
CREATE INDEX idx_san_cert ON subject_alternative_names(certificate_id);
CREATE INDEX idx_ext_cert ON certificate_extensions(certificate_id);

-- Audit lookups
CREATE INDEX idx_audit_cert ON certificate_audit_log(certificate_id);
CREATE INDEX idx_audit_timestamp ON certificate_audit_log(operation_timestamp);

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Certificate Summary View
CREATE VIEW certificate_summary AS
SELECT
    c.id,
    o.org_dir,
    c.cert_name,
    c.cert_type,
    c.subject_common_name,
    c.serial_number,
    c.not_before,
    c.not_after,
    c.status,
    bc.is_ca,
    bc.path_length,
    CASE
        WHEN c.not_after < CURRENT_TIMESTAMP THEN 'expired'
        WHEN c.status = 'revoked' THEN 'revoked'
        ELSE 'valid'
    END AS computed_status,
    julianday(c.not_after) - julianday(CURRENT_TIMESTAMP) AS days_until_expiry
FROM certificates c
JOIN organizations o ON c.organization_id = o.id
LEFT JOIN basic_constraints bc ON c.id = bc.certificate_id;

-- ============================================================================
-- SCHEMA VERSION
-- ============================================================================

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL,
    applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_version (version) VALUES (2);
