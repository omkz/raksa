from fastapi.testclient import TestClient

from app.dependencies import AuthenticatedUser, get_current_user
from app.main import app


def test_health_endpoint() -> None:
    with TestClient(app) as client:
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["app"] == "raksa"


def test_demo_endpoint_reports_real_before_after_proof() -> None:
    with TestClient(app) as client:
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
    auth_user = AuthenticatedUser(
        user={"id": "test_user_id", "login": "test_user"},
        workspace={"id": "default", "name": "Default Workspace"},
        session={"id": "sess_1"},
        role="owner",
    )
    app.dependency_overrides[get_current_user] = lambda: auth_user
    try:
        with TestClient(app) as client:
            demo_res = client.post("/api/scans/demo/run")
            scan_id = demo_res.json()["id"]
            pr_res = client.post(
                f"/api/scans/{scan_id}/pull-request",
                json={"title": "Fix SQLi Vulnerability", "body": "Remediation PR"},
            )
            assert pr_res.status_code == 409
            assert "PR creation is disabled" in pr_res.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_current_user, None)
