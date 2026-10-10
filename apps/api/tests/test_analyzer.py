from app.services.analyzer import apply_exact_replacements, detect_sql_injection


def test_detects_sql_built_with_fstring_variable() -> None:
    files = {
        "app.py": '''def search(connection, name):\n    query = f"SELECT * FROM users WHERE name = '{name}'"\n    return connection.execute(query).fetchall()\n'''
    }
    findings = detect_sql_injection(files)
    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-89"
    assert findings[0]["path"] == "app.py"


def test_does_not_flag_parameterized_query() -> None:
    files = {"app.py": 'connection.execute("SELECT * FROM users WHERE name = ?", (name,))\n'}
    assert detect_sql_injection(files) == []


def test_apply_exact_replacement_requires_unique_match() -> None:
    files = {"app.py": "query = f'SELECT * FROM users WHERE name = {name}'\n"}
    result = apply_exact_replacements(files, [{
        "path": "app.py",
        "old_text": "query = f'SELECT * FROM users WHERE name = {name}'",
        "new_text": 'query = "SELECT * FROM users WHERE name = ?"',
        "reason": "parameterize query",
    }])
    assert "WHERE name = ?" in result["app.py"]


def test_rejects_path_traversal() -> None:
    files = {"app.py": "print('ok')"}
    try:
        apply_exact_replacements(files, [{"path": "../oops.py", "old_text": "print('ok')", "new_text": "x"}])
    except ValueError as exc:
        assert "Unsafe patch path" in str(exc)
    else:
        raise AssertionError("Expected unsafe path to be rejected")
