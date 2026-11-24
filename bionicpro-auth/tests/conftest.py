import json
import time
from urllib.parse import parse_qs, urlparse

import fakeredis
import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

KID = "test-key"
FRONTEND = "http://localhost:3000"


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def settings():
    return Settings(
        keycloak_public_url="http://localhost:8080",
        keycloak_internal_url="http://keycloak:8080",
        keycloak_realm="reports-realm",
        client_id="bionicpro-auth",
        client_secret="test-secret",
        redirect_uri="http://localhost:3000/auth/callback",
        scope="openid profile email",
        frontend_url=FRONTEND,
        redis_url="redis://unused",
        token_encryption_key="",
        cookie_name="bionicpro_session",
        cookie_samesite="lax",
        session_ttl_seconds=1800,
        rotation_grace_seconds=5,
        refresh_margin_seconds=10,
        login_state_ttl_seconds=300,
        reports_api_url="http://reports-api:8000",
    )


class FakeKeycloak:
    """Имитация token, logout и certs endpoint Keycloak поверх respx."""

    def __init__(self, settings: Settings, key, router: respx.Router):
        self.s = settings
        self.key = key
        self.counter = 0
        self.token_requests: list[dict] = []
        self.logout_requests: list[dict] = []
        self.refresh_error = False
        self.expires_in = 120
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
        router.get(settings.jwks_uri).mock(return_value=httpx.Response(200, json={"keys": [jwk]}))
        router.post(settings.token_endpoint).mock(side_effect=self._token)
        router.post(settings.logout_endpoint).mock(side_effect=self._logout)
        self.nonce = None

    def _sign(self, claims: dict) -> str:
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": KID})

    def _tokens(self) -> dict:
        self.counter += 1
        now = int(time.time())
        access = self._sign({"sub": "user-1", "exp": now + self.expires_in, "iat": now,
                             "realm_access": {"roles": ["prothetic_user"]}, "n": self.counter})
        id_token = self._sign({"sub": "user-1", "aud": self.s.client_id, "iss": self.s.issuer,
                               "exp": now + 300, "iat": now, "nonce": self.nonce,
                               "preferred_username": "prothetic1", "email": "prothetic1@example.com"})
        return {"access_token": access, "refresh_token": f"refresh-{self.counter}", "id_token": id_token,
                "expires_in": self.expires_in, "refresh_expires_in": 1800, "token_type": "Bearer"}

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.token_requests.append(form)
        if form["grant_type"] == "refresh_token" and self.refresh_error:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "Session not active"})
        return httpx.Response(200, json=self._tokens())

    def _logout(self, request: httpx.Request) -> httpx.Response:
        self.logout_requests.append({k: v[0] for k, v in parse_qs(request.content.decode()).items()})
        return httpx.Response(204)


@pytest.fixture
def env(settings, rsa_key):
    redis = fakeredis.FakeAsyncRedis()
    with respx.mock(assert_all_called=False) as router:
        kc = FakeKeycloak(settings, rsa_key, router)
        http = httpx.AsyncClient()
        app = create_app(settings, redis=redis, http=http)
        # base_url https: TestClient отправляет Secure cookie только по https.
        with TestClient(app, base_url="https://testserver", follow_redirects=False) as client:
            yield client, kc, router, redis


def do_login(client, kc) -> str:
    """Проходит вход целиком и возвращает выданный session id."""
    resp = client.get("/auth/login")
    query = parse_qs(urlparse(resp.headers["location"]).query)
    kc.nonce = query["nonce"][0]
    resp = client.get("/auth/callback", params={"state": query["state"][0], "code": "auth-code"})
    assert resp.status_code == 302
    return client.cookies.get("bionicpro_session")
