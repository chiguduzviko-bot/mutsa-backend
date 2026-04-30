-- Add/normalize users.role for RBAC.
-- Idempotent migration for PostgreSQL.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type
        WHERE typname = 'user_role_enum'
    ) THEN
        CREATE TYPE user_role_enum AS ENUM ('ADMIN', 'SUPERVISOR', 'INVESTIGATOR');
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'role'
    ) THEN
        ALTER TABLE users
        ADD COLUMN role user_role_enum;
    END IF;
END
$$;

-- Normalize dirty/empty role data to INVESTIGATOR.
UPDATE users
SET role = 'INVESTIGATOR'::user_role_enum
WHERE role IS NULL
   OR TRIM(CAST(role AS TEXT)) = ''
   OR UPPER(TRIM(CAST(role AS TEXT))) NOT IN ('ADMIN', 'SUPERVISOR', 'INVESTIGATOR');

ALTER TABLE users
    ALTER COLUMN role SET DEFAULT 'INVESTIGATOR'::user_role_enum;

ALTER TABLE users
    ALTER COLUMN role SET NOT NULL;
