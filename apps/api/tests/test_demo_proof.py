from app.services.demo_proof import run_demo_proof


def test_demo_proves_sql_injection_before_and_after() -> None:
    result = run_demo_proof()
    assert result["status"] == "verified"
    assert result["before"]["exploit_reproduced"] is True
    assert result["after"]["exploit_blocked"] is True
    assert result["tests"] == {"passed": 2, "total": 2}
