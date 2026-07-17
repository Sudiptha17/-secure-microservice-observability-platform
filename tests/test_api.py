from fastapi.testclient import TestClient

from app.main import app, users_database


client = TestClient(app)


def setup_function():
    users_database.clear()


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "secure-microservice-api",
    }


def test_register_user():
    response = client.post(
        "/register",
        json={
            "username": "test_user",
            "password": "Test123!",
        },
    )

    assert response.status_code == 201
    assert response.json()["username"] == "test_user"


def test_duplicate_registration_is_rejected():
    user = {
        "username": "test_user",
        "password": "Test123!",
    }

    client.post("/register", json=user)
    response = client.post("/register", json=user)

    assert response.status_code == 409
    assert response.json()["detail"] == "Username already exists"


def test_login_returns_jwt():
    client.post(
        "/register",
        json={
            "username": "test_user",
            "password": "Test123!",
        },
    )

    response = client.post(
        "/login",
        data={
            "username": "test_user",
            "password": "Test123!",
        },
    )

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"


def test_protected_route_requires_token():
    response = client.get("/protected")

    assert response.status_code == 401


def test_protected_route_accepts_valid_token():
    client.post(
        "/register",
        json={
            "username": "test_user",
            "password": "Test123!",
        },
    )

    login_response = client.post(
        "/login",
        data={
            "username": "test_user",
            "password": "Test123!",
        },
    )

    token = login_response.json()["access_token"]

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["authenticated_user"] == "test_user"


def test_metrics_endpoint():
    response = client.get("/metrics")

    assert response.status_code == 200
    assert "api_requests_total" in response.text