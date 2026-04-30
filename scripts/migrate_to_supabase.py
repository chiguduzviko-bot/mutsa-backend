"""Migrate data from a source Postgres DB into Supabase Postgres.

Usage (PowerShell):
    $env:SOURCE_DATABASE_URL="postgresql://user:pass@localhost:5432/db"
    $env:TARGET_DATABASE_URL="postgresql://postgres:pass@db.<project>.supabase.co:5432/postgres?sslmode=require"
    ./.venv/Scripts/python scripts/migrate_to_supabase.py
"""

from __future__ import annotations

import os
import re
import sys
from typing import Iterable

import psycopg2
from dotenv import load_dotenv
from psycopg2 import sql
from psycopg2.extras import Json, execute_values

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db

load_dotenv()


def _normalize_dsn(dsn: str) -> str:
    """Convert SQLAlchemy-style DSN to psycopg2 DSN."""
    return dsn.replace("postgresql+psycopg2://", "postgresql://", 1)


def _require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _get_public_tables(conn) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT tablename
            FROM pg_tables
            WHERE schemaname = 'public'
            ORDER BY tablename;
            """
        )
        return [row[0] for row in cur.fetchall()]


def _table_columns(conn, table: str) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = %s
            ORDER BY ordinal_position;
            """,
            (table,),
        )
        return [row[0] for row in cur.fetchall()]


def _chunked(iterable: list[tuple], size: int) -> Iterable[list[tuple]]:
    for i in range(0, len(iterable), size):
        yield iterable[i : i + size]


def _adapt_row_values(row: tuple) -> tuple:
    adapted = []
    for value in row:
        if isinstance(value, (dict, list)):
            adapted.append(Json(value))
        else:
            adapted.append(value)
    return tuple(adapted)


def _set_sequences(target_conn) -> None:
    with target_conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                c.table_name,
                c.column_name,
                pg_get_serial_sequence(format('%I.%I', c.table_schema, c.table_name), c.column_name) AS seq_name
            FROM information_schema.columns c
            WHERE c.table_schema = 'public'
              AND c.column_default LIKE 'nextval(%';
            """
        )
        serial_columns = cur.fetchall()

        for table_name, column_name, seq_name in serial_columns:
            if not seq_name:
                continue
            cur.execute(
                sql.SQL(
                    "SELECT setval(%s, COALESCE((SELECT MAX({col}) FROM {tbl}), 1), true);"
                ).format(
                    col=sql.Identifier(column_name),
                    tbl=sql.Identifier("public", table_name),
                ),
                (seq_name,),
            )


def _sanitize_env_path() -> None:
    # Ensure SSL mode is retained for Supabase; prevent accidental env overrides.
    os.environ["FLASK_ENV"] = os.getenv("FLASK_ENV", "production")


def _create_target_schema(target_dsn_sqlalchemy: str) -> None:
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = target_dsn_sqlalchemy
    _sanitize_env_path()
    app = create_app("production")
    with app.app_context():
        try:
            db.create_all()
        except Exception as exc:
            msg = str(exc).lower()
            if "already exists" in msg or "duplicateobject" in msg:
                print("Target schema objects already exist; continuing.")
            else:
                raise
    if previous is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = previous


def main() -> None:
    source_dsn = _normalize_dsn(_require_env("SOURCE_DATABASE_URL"))
    target_dsn_sqlalchemy = _require_env("TARGET_DATABASE_URL")
    target_dsn = _normalize_dsn(target_dsn_sqlalchemy)

    if not re.search(r"supabase\.co", target_dsn):
        raise RuntimeError("TARGET_DATABASE_URL does not look like a Supabase Postgres URL.")

    print("Creating target schema from SQLAlchemy models...")
    _create_target_schema(target_dsn_sqlalchemy)

    print("Connecting to source and target databases...")
    source_conn = psycopg2.connect(source_dsn)
    target_conn = psycopg2.connect(target_dsn)
    source_conn.autocommit = False
    target_conn.autocommit = False

    try:
        tables = _get_public_tables(source_conn)
        print(f"Found {len(tables)} public tables in source.")

        with target_conn.cursor() as cur:
            cur.execute("SET session_replication_role = replica;")
            if tables:
                identifiers = sql.SQL(", ").join(
                    sql.Identifier("public", table) for table in tables
                )
                cur.execute(sql.SQL("TRUNCATE TABLE {} RESTART IDENTITY CASCADE;").format(identifiers))

        for table in tables:
            columns = _table_columns(source_conn, table)
            if not columns:
                continue

            with source_conn.cursor() as src_cur, target_conn.cursor() as tgt_cur:
                src_cur.execute(
                    sql.SQL("SELECT * FROM {}.{};").format(
                        sql.Identifier("public"), sql.Identifier(table)
                    )
                )
                rows = [_adapt_row_values(row) for row in src_cur.fetchall()]

                if not rows:
                    print(f"[SKIP] {table}: 0 rows")
                    continue

                insert_stmt = sql.SQL("INSERT INTO {}.{} ({}) VALUES %s").format(
                    sql.Identifier("public"),
                    sql.Identifier(table),
                    sql.SQL(", ").join(sql.Identifier(c) for c in columns),
                )
                for batch in _chunked(rows, 1000):
                    execute_values(tgt_cur, insert_stmt, batch, page_size=1000)
                print(f"[OK]   {table}: {len(rows)} rows")

        with target_conn.cursor() as cur:
            _set_sequences(target_conn)
            cur.execute("SET session_replication_role = origin;")

        target_conn.commit()
        source_conn.commit()
        print("Migration completed successfully.")
    except Exception:
        target_conn.rollback()
        source_conn.rollback()
        raise
    finally:
        source_conn.close()
        target_conn.close()


if __name__ == "__main__":
    main()
