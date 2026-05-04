-- Chain-of-Custody users table hardening + optional admin seed.
-- Run in Supabase SQL Editor or psql. Adjust the seed password hash before production.
--
-- If users.role is user_role_enum, run migrations/20260506_fix_user_role_enum_labels.sql FIRST
-- (or the ALTER TYPE block below) so labels like INVESTIGATOR exist.

ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'ADMIN';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'AUDITOR';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'INVESTIGATOR';
ALTER TYPE user_role_enum ADD VALUE IF NOT EXISTS 'AUTHORIZER';

ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);
-- Only applies when `role` does not already exist; if role is enum, this line is skipped.
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50) NOT NULL DEFAULT 'INVESTIGATOR';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

-- Compare as text so missing enum labels do not break constraint creation on enum columns
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check'
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_role_check
      CHECK (role::text IN ('ADMIN', 'INVESTIGATOR', 'AUTHORIZER', 'AUDITOR'));
  END IF;
END $$;

-- Normalize casing for enum role column (requires labels to exist — run enum fix first if needed)
UPDATE users SET role = UPPER(TRIM(role::text))::user_role_enum
WHERE role IS NOT NULL;

-- Seed admin (replace <bcrypt_hash_of_admin> with a real bcrypt hash from the app or seed script).
INSERT INTO users (
  id,
  employee_number,
  full_name,
  email,
  password_hash,
  role,
  is_active,
  created_at,
  updated_at
)
VALUES (
  gen_random_uuid(),
  'EMP-ADMIN-COC',
  'Admin User',
  'admin@coc.gov',
  '<bcrypt_hash_of_admin>',
  'ADMIN'::user_role_enum,
  TRUE,
  NOW(),
  NOW()
)
ON CONFLICT (email) DO NOTHING;
