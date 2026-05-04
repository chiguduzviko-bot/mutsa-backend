-- Run in Supabase SQL Editor after deploying the Flask changes.
--
-- IMPORTANT: extend user_role_enum BEFORE adding CHECK constraints that mention
-- INVESTIGATOR / AUTHORIZER, or Postgres will try to cast those literals to the
-- enum and fail if the label is missing.
-- If you already hit enum errors, run: migrations/20260506_fix_user_role_enum_labels.sql

-- 1) Enum labels (PostgreSQL 15+). Safe to re-run.
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'ADMIN';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'AUDITOR';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'INVESTIGATOR';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'AUTHORIZER';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'SUPERVISOR';

-- 2) Role CHECK uses ::text so Postgres does not require literals to be valid enum members at parse time
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
  CHECK (role::text IN ('ADMIN','AUDITOR','INVESTIGATOR','AUTHORIZER'));

-- 3) Case status enum (skip errors if type name differs)
ALTER TYPE case_status_enum ADD VALUE IF NOT EXISTS 'PENDING_APPROVAL';
ALTER TYPE case_status_enum ADD VALUE IF NOT EXISTS 'OPEN';
ALTER TYPE case_status_enum ADD VALUE IF NOT EXISTS 'UNDER_INVESTIGATION';
ALTER TYPE case_status_enum ADD VALUE IF NOT EXISTS 'REJECTED';
ALTER TYPE case_status_enum ADD VALUE IF NOT EXISTS 'CLOSED';
ALTER TYPE case_status_enum ADD VALUE IF NOT EXISTS 'RESOLVED';
