-- MedicineGuard D1 Phase 4 Schema Migration 0002
-- Phase 4: QR Generation, Customer Verification Audit & Batch Revocation

-- 1. Backup all affected tables
CREATE TABLE batches_bk AS SELECT * FROM batches;
CREATE TABLE medicine_units_bk AS SELECT * FROM medicine_units;
CREATE TABLE verification_logs_bk AS SELECT * FROM verification_logs;
CREATE TABLE batch_events_bk AS SELECT * FROM batch_events;

-- 2. Drop dependent child tables in reverse dependency order
DROP TABLE verification_logs;
DROP TABLE batch_events;
DROP TABLE medicine_units;
DROP TABLE batches;

-- 3. Recreate batches with 'revoked' publication_status, revoked_at, and revocation_reason
CREATE TABLE batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT UNIQUE NOT NULL,
    manufacturer_user_id TEXT NOT NULL REFERENCES users(user_id),
    medicine_name TEXT NOT NULL,
    manufacturing_date TEXT NOT NULL,
    expiry_date TEXT NOT NULL,
    total_units INTEGER NOT NULL,
    merkle_root TEXT NOT NULL,
    algorithm_version TEXT NOT NULL DEFAULT 'MG01+MGP1+SHA256',
    publication_status TEXT NOT NULL CHECK(publication_status IN ('uploading', 'published', 'aborted', 'revoked')) DEFAULT 'uploading',
    created_at TEXT NOT NULL,
    published_at TEXT,
    revoked_at TEXT,
    revocation_reason TEXT
);

INSERT INTO batches (id, batch_id, manufacturer_user_id, medicine_name, manufacturing_date, expiry_date, total_units, merkle_root, algorithm_version, publication_status, created_at, published_at)
SELECT id, batch_id, manufacturer_user_id, medicine_name, manufacturing_date, expiry_date, total_units, merkle_root, algorithm_version, publication_status, created_at, published_at FROM batches_bk;

CREATE INDEX idx_batches_batch_id ON batches(batch_id);
CREATE INDEX idx_batches_pub_status ON batches(publication_status);
CREATE INDEX idx_batches_mfg_user ON batches(manufacturer_user_id);

-- 4. Recreate medicine_units
CREATE TABLE medicine_units (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_db_id INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    batch_id TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    medicine_name TEXT NOT NULL,
    manufacturing_date TEXT NOT NULL,
    expiry_date TEXT NOT NULL,
    proof_data TEXT NOT NULL,
    verification_reference TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(batch_db_id, unit_id),
    UNIQUE(batch_db_id, leaf_index)
);

INSERT INTO medicine_units (id, batch_db_id, batch_id, unit_id, leaf_index, medicine_name, manufacturing_date, expiry_date, proof_data, verification_reference, created_at)
SELECT id, batch_db_id, batch_id, unit_id, leaf_index, medicine_name, manufacturing_date, expiry_date, proof_data, verification_reference, created_at FROM medicine_units_bk;

CREATE INDEX idx_medicine_units_unit_id ON medicine_units(unit_id);
CREATE INDEX idx_medicine_units_lookup ON medicine_units(unit_id, batch_id);
CREATE INDEX idx_medicine_units_verif_ref ON medicine_units(verification_reference);
CREATE INDEX idx_medicine_units_batch_db_id ON medicine_units(batch_db_id);

-- 5. Recreate verification_logs
CREATE TABLE verification_logs (
    verification_id TEXT PRIMARY KEY,
    unit_db_id INTEGER REFERENCES medicine_units(id),
    batch_db_id INTEGER REFERENCES batches(id),
    pharmacist_user_id TEXT NOT NULL REFERENCES users(user_id),
    client_verification_result TEXT NOT NULL,
    client_status_code INTEGER,
    server_verification_result TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    ip_hash TEXT,
    user_agent TEXT
);

INSERT INTO verification_logs (verification_id, unit_db_id, batch_db_id, pharmacist_user_id, client_verification_result, client_status_code, server_verification_result, timestamp, ip_hash, user_agent)
SELECT verification_id, unit_db_id, batch_db_id, pharmacist_user_id, client_verification_result, client_status_code, server_verification_result, timestamp, ip_hash, user_agent FROM verification_logs_bk;

CREATE INDEX idx_verification_logs_timestamp ON verification_logs(timestamp);
CREATE INDEX idx_verification_logs_pharmacist ON verification_logs(pharmacist_user_id);
CREATE INDEX idx_verification_logs_unit ON verification_logs(unit_db_id);

-- 6. Recreate batch_events
CREATE TABLE batch_events (
    event_id TEXT PRIMARY KEY,
    batch_db_id INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor_user_id TEXT NOT NULL REFERENCES users(user_id),
    details TEXT,
    created_at TEXT NOT NULL
);

INSERT INTO batch_events (event_id, batch_db_id, event_type, actor_user_id, details, created_at)
SELECT event_id, batch_db_id, event_type, actor_user_id, details, created_at FROM batch_events_bk;

CREATE INDEX idx_batch_events_batch ON batch_events(batch_db_id);

-- 7. Drop backup tables
DROP TABLE verification_logs_bk;
DROP TABLE batch_events_bk;
DROP TABLE medicine_units_bk;
DROP TABLE batches_bk;

-- 8. Create Customer Verifications Table
CREATE TABLE customer_verifications (
    id TEXT PRIMARY KEY,
    verification_reference TEXT NOT NULL,
    unit_db_id INTEGER REFERENCES medicine_units(id),
    batch_db_id INTEGER REFERENCES batches(id),
    verification_result TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    ip_hash TEXT,
    user_agent TEXT
);

CREATE INDEX idx_cust_verif_ref ON customer_verifications(verification_reference);
CREATE INDEX idx_cust_verif_timestamp ON customer_verifications(timestamp);
CREATE INDEX idx_cust_verif_batch ON customer_verifications(batch_db_id);
