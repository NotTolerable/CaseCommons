import os
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text


@pytest.mark.integration
def test_flask_db_upgrade_on_fresh_postgres():
    db_url = os.environ.get("TEST_DATABASE_URL")
    if not db_url:
        pytest.skip("TEST_DATABASE_URL not provided for migration integration test")
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    if not db_url.startswith("postgresql://"):
        pytest.skip("Migration integration test expects a Postgres database URL")

    engine = create_engine(db_url)

    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))

    env = os.environ.copy()
    env["DATABASE_URL"] = db_url
    env.setdefault("FLASK_APP", "app:create_app")
    subprocess.check_call(["flask", "db", "upgrade"], cwd=Path(__file__).resolve().parents[1], env=env)

    with engine.connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
                )
            )
        }

    expected_tables = {
        "user",
        "report",
        "discussion",
        "comment",
        "report_image",
        "email_token",
        "moderation_log",
    }
    assert expected_tables.issubset(tables)
