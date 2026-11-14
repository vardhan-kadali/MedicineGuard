-- MedicineGuard D1 Initial Schema Migration 0001
-- Phase 3D: Backend, Authentication & Shared Trusted Batch Registry

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_algorithm TEXT NOT NULL DEFAULT 'PBKDF2-SHA256',
    password_iterations INTEGER NOT NULL DEFAULT 600000,
    role TEXT NOT NULL CHECK(role IN ('admin', 'manufacturer', 'pharmacist')),
    account_status TEXT NOT NULL CHECK(account_status IN ('active', 'disabled')) DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- 2. Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    csrf_token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- 3. Batches Table
CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT UNIQUE NOT NULL,
    manufacturer_user_id TEXT NOT NULL REFERENCES users(user_id),
    medicine_name TEXT NOT NULL,
    manufacturing_date TEXT NOT NULL,
    expiry_date TEXT NOT NULL,
    total_units INTEGER NOT NULL,
    merkle_root TEXT NOT NULL,
    algorithm_version TEXT NOT NULL DEFAULT 'MG01+MGP1+SHA256',
    publication_status TEXT NOT NULL CHECK(publication_status IN ('uploading', 'published', 'aborted')) DEFAULT 'uploading',
    created_at TEXT NOT NULL,
    published_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_batches_batch_id ON batches(batch_id);
CREATE INDEX IF NOT EXISTS idx_batches_pub_status ON batches(publication_status);
CREATE INDEX IF NOT EXISTS idx_batches_mfg_user ON batches(manufacturer_user_id);

-- 4. Medicine Units Table
CREATE TABLE IF NOT EXISTS medicine_units (
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

CREATE INDEX IF NOT EXISTS idx_medicine_units_unit_id ON medicine_units(unit_id);
CREATE INDEX IF NOT EXISTS idx_medicine_units_lookup ON medicine_units(unit_id, batch_id);
CREATE INDEX IF NOT EXISTS idx_medicine_units_verif_ref ON medicine_units(verification_reference);
CREATE INDEX IF NOT EXISTS idx_medicine_units_batch_db_id ON medicine_units(batch_db_id);

-- 5. Verification Logs Table
CREATE TABLE IF NOT EXISTS verification_logs (
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

CREATE INDEX IF NOT EXISTS idx_verification_logs_timestamp ON verification_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_verification_logs_pharmacist ON verification_logs(pharmacist_user_id);
CREATE INDEX IF NOT EXISTS idx_verification_logs_unit ON verification_logs(unit_db_id);

-- 6. Batch Events Table
CREATE TABLE IF NOT EXISTS batch_events (
    event_id TEXT PRIMARY KEY,
    batch_db_id INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor_user_id TEXT NOT NULL REFERENCES users(user_id),
    details TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_batch_events_batch ON batch_events(batch_db_id);

