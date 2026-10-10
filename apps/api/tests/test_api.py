from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["app"] == "raksa"


def test_demo_endpoint_reports_real_before_after_proof() -> None:
    client = TestClient(app)
    response = client.post("/api/scans/demo/run")
    assert response.status_code == 200
    data = response.json()
    assert data["verification"]["status"] == "verified"
    assert data["verification"]["before"]["exploit_reproduced"] is True
    assert data["verification"]["after"]["exploit_blocked"] is True
    assert data["verification"]["eligible_for_pr"] is False
    assert data["verification"]["static_recheck"]["passed"] is True
    assert data["verification"]["security_exploit"]["passed"] is True
    assert data["verification"]["regression_tests"]["passed"] is True


def test_pull_request_blocked_when_not_eligible() -> None:
    client = TestClient(app)
    demo_res = client.post("/api/scans/demo/run")
    scan_id = demo_res.json()["id"]
    pr_res = client.post(f"/api/scans/{scan_id}/pull-request", json={"title": "Fix SQLi", "body": "Remediation PR"})
    assert pr_res.status_code == 409
    assert "PR creation is disabled" in pr_res.json()["detail"]
