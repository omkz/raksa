import sqlite3
import unittest

from app import search_users_fixed, search_users_vulnerable


class SQLInjectionDemoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
        self.db.executemany("INSERT INTO users(name) VALUES (?)", [("alice",), ("bob",), ("charlie",)])

    def tearDown(self) -> None:
        self.db.close()

    def test_vulnerable_query_returns_all_users_for_injection_payload(self) -> None:
        rows = search_users_vulnerable(self.db, "' OR 1=1 --")
        self.assertEqual(len(rows), 3)

    def test_parameterized_query_treats_payload_as_literal(self) -> None:
        rows = search_users_fixed(self.db, "' OR 1=1 --")
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
