-- Migration BLOCK B: backfill, defaults, indexes, audit_trail columns, flags table.
-- Run AFTER block A has been committed to the DB.

-- Backfill legacy roles to AUDITOR
UPDATE users
SET role = 'AUDITOR'::user_role_enum
WHERE role::text IN ('INVESTIGATOR', 'SUPERVISOR')
   OR role IS NULL
   OR TRIM(role::text) = '';

-- Set AUDITOR as default, enforce NOT NULL
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'AUDITOR'::user_role_enum;
ALTER TABLE users ALTER COLUMN role SET NOT NULL;

-- Index on role for fast RBAC lookups
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);

-- Extend audit_trail with richer columns
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_trail' AND column_name = 'actor_role'
    ) THEN
        ALTER TABLE audit_trail ADD COLUMN actor_role VARCHAR(20);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_trail' AND column_name = 'evidence_id'
    ) THEN
        ALTER TABLE audit_trail
            ADD COLUMN evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_trail' AND column_name = 'case_id'
    ) THEN
        ALTER TABLE audit_trail
            ADD COLUMN case_id UUID REFERENCES cases(id) ON DELETE SET NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_trail' AND column_name = 'hash_at_time'
    ) THEN
        ALTER TABLE audit_trail ADD COLUMN hash_at_time CHAR(64);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_trail' AND column_name = 'metadata'
    ) THEN
        ALTER TABLE audit_trail
            ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}'::JSONB;
    END IF;
END
$$;

-- Create audit_log_flags table
CREATE TABLE IF NOT EXISTS audit_log_flags (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_log_id       UUID NOT NULL
                           REFERENCES evidence_access_log(id) ON DELETE CASCADE,
    flagged_by_user_id UUID NOT NULL REFERENCES users(id),
    reason             TEXT NOT NULL,
    category           VARCHAR(40) NOT NULL DEFAULT 'OTHER'
                           CHECK (category IN ('HASH_MISMATCH', 'UNUSUAL_ACCESS', 'OTHER')),
    status             VARCHAR(20) NOT NULL DEFAULT 'OPEN'
                           CHECK (status IN ('OPEN', 'REVIEWED', 'DISMISSED')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_flags_audit_log_id
    ON audit_log_flags (audit_log_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_flags_flagged_by
    ON audit_log_flags (flagged_by_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_flags_status
    ON audit_log_flags (status);
