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
