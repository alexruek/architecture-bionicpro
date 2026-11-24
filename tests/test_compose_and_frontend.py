"""docker-compose, фронтенд и bionicpro-auth используют значения из config/defaults.toml."""

import json
import re

from conftest import ROOT


def test_auth_service_environment(auth_env, auth_client, defaults):
    kc, ac, s = defaults["keycloak"], defaults["auth_client"], defaults["session"]
    expected = {
        "KEYCLOAK_PUBLIC_URL": kc["public_url"],
        "KEYCLOAK_INTERNAL_URL": kc["internal_url"],
        "KEYCLOAK_REALM": kc["realm"],
        "OIDC_CLIENT_ID": ac["client_id"],
        "OIDC_REDIRECT_URI": ac["redirect_uri"],
        "OIDC_SCOPE": ac["scope"],
        "FRONTEND_URL": ac["frontend_url"],
        "REDIS_URL": defaults["redis"]["url"],
        "SESSION_COOKIE_NAME": s["cookie_name"],
        "SESSION_COOKIE_SAMESITE": s["cookie_samesite"],
        "SESSION_TTL_SECONDS": str(s["ttl_seconds"]),
        "SESSION_ROTATION_GRACE_SECONDS": str(s["rotation_grace_seconds"]),
        "ACCESS_TOKEN_REFRESH_MARGIN_SECONDS": str(s["refresh_margin_seconds"]),
        "LOGIN_STATE_TTL_SECONDS": str(s["login_state_ttl_seconds"]),
        "REPORTS_API_URL": defaults["reports_api"]["upstream_url"],
    }
    for key, value in expected.items():
        assert auth_env[key] == value, key
    assert auth_env["OIDC_CLIENT_SECRET"] == auth_client["secret"]


def test_session_outlives_access_token(defaults):
    s, kc = defaults["session"], defaults["keycloak"]
    assert s["ttl_seconds"] > kc["access_token_lifespan_seconds"]
    assert s["ttl_seconds"] <= kc["sso_session_idle_timeout_seconds"]
    assert s["refresh_margin_seconds"] < kc["access_token_lifespan_seconds"]
    assert s["rotation_grace_seconds"] < kc["access_token_lifespan_seconds"]


def test_keycloak_service(compose, defaults):
    kc = compose["services"]["keycloak"]
    assert kc["environment"]["KC_HOSTNAME_URL"] == defaults["keycloak"]["public_url"]
    assert kc["build"]["context"] == "./keycloak"
    assert "openldap" in kc["depends_on"]
    assert "redis" in compose["services"]


def test_redirect_uri_points_to_frontend(defaults):
    ac = defaults["auth_client"]
    assert ac["redirect_uri"] == ac["frontend_url"] + "/auth/callback"


def test_pkce_method_in_code(defaults):
    code = (ROOT / "bionicpro-auth" / "app" / "pkce.py").read_text(encoding="utf-8")
    assert f'CODE_CHALLENGE_METHOD = "{defaults["pkce"]["code_challenge_method"]}"' in code


def test_frontend_has_no_keycloak_integration():
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    assert not [d for d in package["dependencies"] if "keycloak" in d]
    for path in (ROOT / "frontend" / "src").rglob("*.ts*"):
        text = path.read_text(encoding="utf-8")
        assert "keycloak" not in text.lower(), path.name
        assert "Authorization" not in text, path.name
        assert "localStorage" not in text and "sessionStorage" not in text, path.name


def test_frontend_proxies_auth_and_api():
    conf = (ROOT / "frontend" / "nginx.conf").read_text(encoding="utf-8")
    for prefix in ("/auth/", "/api/"):
        block = re.search(r"location " + re.escape(prefix) + r" \{(.*?)\}", conf, re.S).group(1)
        assert "proxy_pass http://bionicpro-auth:8000;" in block
    assert "Access-Control-Allow-Origin" not in conf
