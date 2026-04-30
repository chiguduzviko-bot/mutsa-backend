import os

import psycopg2
from dotenv import load_dotenv

load_dotenv()

dsn = os.getenv("TARGET_DATABASE_URL") or os.getenv("DATABASE_URL")
if not dsn:
    raise RuntimeError("Missing TARGET_DATABASE_URL or DATABASE_URL")
dsn = dsn.replace("postgresql+psycopg2://", "postgresql://", 1)

sql_statements = [
    "UPDATE users SET role = UPPER(role::text)::user_role_enum;",
    "ALTER TABLE users DROP CONSTRAINT IF EXISTS role_uppercase;",
    "ALTER TABLE users ADD CONSTRAINT role_uppercase CHECK (role::text = UPPER(role::text));",
    """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'fraud_type_enum' AND e.enumlabel = 'IDENTITY_THEFT'
      ) THEN
        ALTER TYPE fraud_type_enum ADD VALUE 'IDENTITY_THEFT';
      END IF;

      IF NOT EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'fraud_type_enum' AND e.enumlabel = 'FINANCIAL_FRAUD'
      ) THEN
        ALTER TYPE fraud_type_enum ADD VALUE 'FINANCIAL_FRAUD';
      END IF;

      IF NOT EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'fraud_type_enum' AND e.enumlabel = 'CYBERCRIME'
      ) THEN
        ALTER TYPE fraud_type_enum ADD VALUE 'CYBERCRIME';
      END IF;

      IF NOT EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'fraud_type_enum' AND e.enumlabel = 'MONEY_LAUNDERING'
      ) THEN
        ALTER TYPE fraud_type_enum ADD VALUE 'MONEY_LAUNDERING';
      END IF;

      IF NOT EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'fraud_type_enum' AND e.enumlabel = 'OTHER'
      ) THEN
        ALTER TYPE fraud_type_enum ADD VALUE 'OTHER';
      END IF;
    END
    $$;
    """,
]

with psycopg2.connect(dsn) as conn:
    with conn.cursor() as cur:
        for statement in sql_statements:
            cur.execute(statement)
        cur.execute("SELECT id, email, role::text FROM users ORDER BY email;")
        rows = cur.fetchall()

print("Users/roles:")
for row in rows:
    print(row)
print("Supabase SQL fixes applied.")
