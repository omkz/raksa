import sqlite3
from typing import Any

VULNERABLE_SNIPPET = "query = f\"SELECT id, name FROM users WHERE name = '{name}'\"\nrows = connection.execute(query).fetchall()"
FIXED_SNIPPET = 'query = "SELECT id, name FROM users WHERE name = ?"\nrows = connection.execute(query, (name,)).fetchall()'


def _build_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
    db.executemany("INSERT INTO users(name) VALUES (?)", [("alice",), ("bob",), ("charlie",)])
    return db


def run_demo_proof() -> dict[str, Any]:
    payload = "' OR 1=1 --"
    db = _build_db()
    vulnerable_query = f"SELECT id, name FROM users WHERE name = '{payload}'"
    vulnerable_rows = db.execute(vulnerable_query).fetchall()
    db.close()

    db = _build_db()
    safe_query = "SELECT id, name FROM users WHERE name = ?"
    safe_rows = db.execute(safe_query, (payload,)).fetchall()
    db.close()

    reproduced = len(vulnerable_rows) == 3
    blocked = len(safe_rows) == 0
    passed = reproduced and blocked
    return {
        "status": "verified" if passed else "failed",
        "vulnerability": "SQL Injection (CWE-89)",
        "payload": payload,
        "before": {"result_count": len(vulnerable_rows), "expected": "Payload returns unintended rows", "exploit_reproduced": reproduced},
        "after": {"result_count": len(safe_rows), "expected": "Payload treated as a literal value", "exploit_blocked": blocked},
        "tests": {"passed": int(reproduced) + int(blocked), "total": 2},
        "evidence": "A controlled in-memory SQLite proof. This does not execute repository code or prove arbitrary findings.",
    }
