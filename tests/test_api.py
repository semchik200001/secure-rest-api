import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app import create_app
from app.db import get_db

SECRET = "test-secret-key-that-is-long-enough-for-hs256"
PASSWORD = "Str0ng-Passw0rd"


@pytest.fixture
def app(tmp_path):
    return create_app({"DATABASE": str(tmp_path / "test.sqlite3"), "JWT_SECRET": SECRET})


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def token(client):
    client.post("/auth/register", json={"username": "alice", "password": PASSWORD})
    resp = client.post("/auth/login", json={"username": "alice", "password": PASSWORD})
    return resp.get_json()["access_token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_register_and_login(client):
    resp = client.post("/auth/register", json={"username": "bob", "password": PASSWORD})
    assert resp.status_code == 201

    resp = client.post("/auth/login", json={"username": "bob", "password": PASSWORD})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"]


def test_password_is_stored_as_bcrypt_hash(app, client):
    client.post("/auth/register", json={"username": "bob", "password": PASSWORD})
    with app.app_context():
        row = get_db().execute("SELECT password_hash FROM users WHERE username = 'bob'").fetchone()
    assert row["password_hash"] != PASSWORD
    assert row["password_hash"].startswith("$2b$12$")


def test_duplicate_user_rejected(client):
    client.post("/auth/register", json={"username": "bob", "password": PASSWORD})
    resp = client.post("/auth/register", json={"username": "bob", "password": PASSWORD})
    assert resp.status_code == 409


def test_weak_password_rejected(client):
    resp = client.post("/auth/register", json={"username": "bob", "password": "123"})
    assert resp.status_code == 400


def test_login_wrong_password(client, token):
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong-password"})
    assert resp.status_code == 401


def test_login_unknown_user_same_message(client, token):
    wrong_pass = client.post("/auth/login", json={"username": "alice", "password": "wrong-password"})
    no_user = client.post("/auth/login", json={"username": "nobody", "password": "wrong-password"})
    assert wrong_pass.get_json() == no_user.get_json()


def test_login_sql_injection(client, token):
    resp = client.post("/auth/login", json={"username": "alice' OR '1'='1' --", "password": "x"})
    assert resp.status_code == 401


def test_data_requires_token(client):
    resp = client.get("/api/data")
    assert resp.status_code == 401


def test_data_with_valid_token(client, token):
    resp = client.get("/api/data", headers=auth(token))
    assert resp.status_code == 200
    assert resp.get_json()["user"] == "alice"


def test_invalid_token_rejected(client):
    resp = client.get("/api/data", headers=auth("not.a.token"))
    assert resp.status_code == 401


def test_token_with_wrong_signature_rejected(client, token):
    forged = jwt.encode(
        {"sub": "1", "iat": datetime.now(timezone.utc), "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        "another-secret-key-that-is-long-enough-for-hs256",
        algorithm="HS256",
    )
    resp = client.get("/api/data", headers=auth(forged))
    assert resp.status_code == 401


def test_alg_none_token_rejected(client, token):
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    exp = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
    unsigned = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': '1', 'iat': 0, 'exp': exp})}."
    resp = client.get("/api/data", headers=auth(unsigned))
    assert resp.status_code == 401


def test_expired_token_rejected(client, token):
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    expired = jwt.encode({"sub": "1", "iat": past, "exp": past + timedelta(minutes=1)}, SECRET, algorithm="HS256")
    resp = client.get("/api/data", headers=auth(expired))
    assert resp.status_code == 401
    assert "истёк" in resp.get_json()["error"]


def test_create_post_requires_token(client):
    resp = client.post("/api/posts", json={"title": "t", "body": "b"})
    assert resp.status_code == 401


def test_create_post_and_xss_is_escaped(client, token):
    payload = {"title": "<script>alert(1)</script>", "body": '<img src=x onerror="alert(1)">'}
    resp = client.post("/api/posts", json=payload, headers=auth(token))
    assert resp.status_code == 201
    post = resp.get_json()
    assert post["title"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert "<img" not in post["body"]

    data = client.get("/api/data", headers=auth(token)).get_json()
    assert data["posts"][0]["title"] == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_create_post_validation(client, token):
    resp = client.post("/api/posts", json={"title": "", "body": "b"}, headers=auth(token))
    assert resp.status_code == 400
    resp = client.post("/api/posts", json={"title": 123, "body": "b"}, headers=auth(token))
    assert resp.status_code == 400


def test_sql_injection_in_post_is_stored_as_text(app, client, token):
    payload = {"title": "x'); DROP TABLE users; --", "body": "test"}
    resp = client.post("/api/posts", json=payload, headers=auth(token))
    assert resp.status_code == 201
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def test_security_headers(client):
    resp = client.get("/api/data")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in resp.headers["Content-Security-Policy"]
