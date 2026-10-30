"""CWE-22 verification is explicit, scoped, and fail-closed."""

from app.services.cwe22_verifier import assess_cwe22_candidate


def test_static_demo_fixture_never_claims_verified() -> None:
    original = (
        '"""STATIC SCAN FIXTURE ONLY — intentionally unsafe; never execute or deploy."""\n'
        "def read_file(name):\n    return open(name).read()\n"
    )
    patched = original.replace("open(name)", "open(name, encoding='utf-8')")
    evidence = assess_cwe22_candidate(
        path="src/unsafe_path.py", original=original,
        patched=patched, authorized_root="uploads/",
    )
    assert evidence["status"] == "unverified"
    assert evidence["eligible_for_pr"] is False
    assert evidence["security_exploit"]["status"] == "not_run"
    assert evidence["regression_tests"]["status"] == "not_run"
    assert "must not be executed" in evidence["message"]


def test_candidate_cannot_claim_verified_from_open_call_absence() -> None:
    original = "def read_file(name):\n    return open(name).read()\n"
    patched = "def read_file(name):\n    return 'placeholder'\n"
    evidence = assess_cwe22_candidate(
        path="src/file.py", original=original,
        patched=patched, authorized_root="uploads/",
    )
    assert evidence["static_recheck"]["details"]["source_open_call_count"] == 0
    assert evidence["status"] == "unverified"
    assert evidence["eligible_for_pr"] is False


def test_broken_python_is_failed_not_verified() -> None:
    original = "def read_file(name):\n    return open(name).read()\n"
    patched = "def read_file(name):\n  if (\n"
    evidence = assess_cwe22_candidate(
        path="src/file.py", original=original,
        patched=patched, authorized_root="uploads/",
    )
    assert evidence["status"] == "failed"
    assert evidence["eligible_for_pr"] is False
    assert evidence["static_recheck"]["status"] == "failed"
