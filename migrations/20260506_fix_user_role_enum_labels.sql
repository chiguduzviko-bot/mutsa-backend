-- Run this FIRST if you see:
--   ERROR: invalid input value for enum user_role_enum: "INVESTIGATOR"
-- Extends PostgreSQL enum labels before any CHECK, DEFAULT, or app inserts use them.
-- Supabase / PostgreSQL 15+ (ADD VALUE IF NOT EXISTS).

ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'ADMIN';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'AUDITOR';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'INVESTIGATOR';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'AUTHORIZER';

-- Legacy label from older migrations (optional; skip if this errors "already exists" with different meaning)
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'SUPERVISOR';
