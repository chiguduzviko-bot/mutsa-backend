-- Migration BLOCK A: extend user_role_enum with AUDITOR label.
-- Must be committed before block B uses the new label in DML.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum
        WHERE enumlabel = 'AUDITOR'
          AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'user_role_enum')
    ) THEN
        ALTER TYPE user_role_enum ADD VALUE 'AUDITOR';
    END IF;
END
$$;
