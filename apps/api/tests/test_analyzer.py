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


def test_skips_test_files_and_demo_fixtures() -> None:
    vulnerable_snippet = 'def search(c, n):\n    q = f"SELECT * FROM u WHERE name = \'{n}\'"\n    return c.execute(q).fetchall()\n'
    files = {
        "tests/test_search.py": vulnerable_snippet,
        "app/services/demo_proof.py": vulnerable_snippet,
        "examples/sample/app.py": vulnerable_snippet,
        "fixture.py": "# INTENTIONAL VULNERABILITY\n" + vulnerable_snippet,
        "real_app/views.py": vulnerable_snippet,
    }
    findings = detect_sql_injection(files)
    assert len(findings) == 1
    assert findings[0]["path"] == "real_app/views.py"


def test_validate_patch_proposal_strict_path() -> None:
    from app.services.analyzer import validate_patch_proposal
    source = "def foo():\n    return 1\n"

    # Missing path
    proposal_missing = {
        "old_text": "    return 1",
        "new_text": "    return 2",
    }
    validated, error = validate_patch_proposal(proposal_missing, "app.py", source)
    assert validated is None
    assert error is not None
    assert "Wrong path" in error
    assert "missing" in error

    # Wrong path
    proposal_wrong = {
        "path": "wrong.py",
        "old_text": "    return 1",
        "new_text": "    return 2",
    }
    validated, error = validate_patch_proposal(proposal_wrong, "app.py", source)
    assert validated is None
    assert error is not None
    assert "Wrong path" in error
    assert "targets 'wrong.py'" in error

    # Correct path
    proposal_correct = {
        "path": "app.py",
        "old_text": "    return 1",
        "new_text": "    return 2",
    }
    validated, error = validate_patch_proposal(proposal_correct, "app.py", source)
    assert error is None
    assert validated is not None
    assert validated["path"] == "app.py"
    assert validated["new_text"] == "    return 2"
