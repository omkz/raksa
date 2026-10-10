"""Intentionally vulnerable teaching example. Never expose this app to a network."""

import sqlite3


def search_users_vulnerable(connection: sqlite3.Connection, name: str) -> list[tuple[int, str]]:
    # INTENTIONAL VULNERABILITY: demonstrates SQL injection in a disposable fixture.
    query = f"SELECT id, name FROM users WHERE name = '{name}'"
    return connection.execute(query).fetchall()


def search_users_fixed(connection: sqlite3.Connection, name: str) -> list[tuple[int, str]]:
    query = "SELECT id, name FROM users WHERE name = ?"
    return connection.execute(query, (name,)).fetchall()
