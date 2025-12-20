import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path

import psycopg2
import pytest


def _find_free_port():
    sock = socket.socket()
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _wait_for_db(uri, timeout=45):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            conn = psycopg2.connect(uri)
            conn.close()
            return
        except psycopg2.OperationalError as exc:  # pragma: no cover - retry loop
            last_error = exc
            time.sleep(1)
    raise AssertionError(f"Database did not become ready: {last_error}")


def _seed_marker(uri, marker):
    conn = psycopg2.connect(uri)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS persistence_probe (id serial PRIMARY KEY, marker text NOT NULL)")
    cur.execute("INSERT INTO persistence_probe (marker) VALUES (%s) RETURNING id", (marker,))
    row_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return row_id


def _assert_marker_exists(uri, marker):
    conn = psycopg2.connect(uri)
    cur = conn.cursor()
    cur.execute("SELECT marker FROM persistence_probe WHERE marker=%s", (marker,))
    found = cur.fetchone()
    cur.close()
    conn.close()
    assert found is not None


@pytest.mark.integration
def test_docker_compose_restart_retains_data():
    if os.environ.get("RUN_DOCKER_INTEGRATION") != "1":
        pytest.skip("set RUN_DOCKER_INTEGRATION=1 to run docker persistence checks")
    if not shutil.which("docker"):
        pytest.skip("docker is not available in this environment")

    project_root = Path(__file__).resolve().parents[1]
    project_name = f"ccpersist_{uuid.uuid4().hex[:8]}"
    db_port = _find_free_port()
    db_url = f"postgresql://postgres:postgres@localhost:{db_port}/casecommons"

    env = os.environ.copy()
    env.update({
        "COMPOSE_PROJECT_NAME": project_name,
        "DB_PORT": str(db_port),
        "DATABASE_URL": db_url,
    })

    subprocess.run(["docker", "compose", "-f", "docker-compose.yml", "up", "-d", "db"], cwd=project_root, env=env, check=True)
    try:
        _wait_for_db(db_url)
        marker = f"mk-{uuid.uuid4().hex}"
        _seed_marker(db_url, marker)

        subprocess.run(["docker", "compose", "-f", "docker-compose.yml", "restart", "db"], cwd=project_root, env=env, check=True)
        _wait_for_db(db_url)
        _assert_marker_exists(db_url, marker)
    finally:
        subprocess.run(["docker", "compose", "-f", "docker-compose.yml", "down", "-v"], cwd=project_root, env=env, check=False)
