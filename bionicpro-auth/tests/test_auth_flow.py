import re
from urllib.parse import parse_qs, urlparse

import httpx

from app.pkce import code_challenge
from conftest import FRONTEND, do_login


def _cookie_header(resp, name="bionicpro_session") -> str:
    return next(h for h in resp.headers.get_list("set-cookie") if h.startswith(name + "="))


def test_login_redirects_with_pkce_s256(env):
    client, kc, _, redis = env
    resp = client.get("/auth/login")
    assert resp.status_code == 302
    url = urlparse(resp.headers["location"])
    assert f"{url.scheme}://{url.netloc}{url.path}" == (
        "http://localhost:8080/realms/reports-realm/protocol/openid-connect/auth")
    query = parse_qs(url.query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["response_type"] == ["code"]
    assert len(query["code_challenge"][0]) == 43
    state_cookie = _cookie_header(resp, "bionicpro_login_state")
    assert "HttpOnly" in state_cookie and "Secure" in state_cookie


def test_login_passes_idp_hint(env):
    client, *_ = env
    resp = client.get("/auth/login", params={"idp": "yandex"})
    assert parse_qs(urlparse(resp.headers["location"]).query)["kc_idp_hint"] == ["yandex"]
    assert client.get("/auth/login", params={"idp": "../evil"}).status_code == 400


def test_callback_sends_code_verifier_and_sets_cookie_without_tokens(env):
    client, kc, _, redis = env
    resp = client.get("/auth/login")
    query = parse_qs(urlparse(resp.headers["location"]).query)
    kc.nonce = query["nonce"][0]
    resp = client.get("/auth/callback", params={"state": query["state"][0], "code": "auth-code"})
    assert resp.status_code == 302
    assert resp.headers["location"] == FRONTEND + "/"
    form = kc.token_requests[0]
    assert form["grant_type"] == "authorization_code"
    assert code_challenge(form["code_verifier"]) == query["code_challenge"][0]
    cookie = _cookie_header(resp)
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    max_age = int(re.search(r"Max-Age=(\d+)", cookie).group(1))
    # Сессия живет дольше access_token (120 с), но не дольше refresh_token (1800 с).
    assert 120 < max_age <= 1800
    assert "access_token" not in resp.text and "refresh" not in resp.text


def test_tokens_are_encrypted_in_redis(env):
    client, kc, _, redis = env
    do_login(client, kc)
    import asyncio

    async def dump():
        values = []
        for key in await redis.keys("*"):
            values.append(await redis.get(key))
        return b" ".join(values)

    blob = asyncio.run(dump())
    assert b"refresh-1" not in blob
    assert b"eyJ" not in blob  # ни одного JWT в открытом виде


def test_callback_rejects_foreign_state(env):
    client, kc, *_ = env
    client.get("/auth/login")
    resp = client.get("/auth/callback", params={"state": "other", "code": "x"})
    assert resp.status_code == 400
    assert kc.token_requests == []


def test_callback_rejects_wrong_nonce(env):
    client, kc, *_ = env
    resp = client.get("/auth/login")
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    kc.nonce = "something-else"
    resp = client.get("/auth/callback", params={"state": state, "code": "x"})
    assert resp.status_code == 401
    assert client.cookies.get("bionicpro_session") is None


def test_session_endpoint_rotates_session_id(env):
    client, kc, *_ = env
    first = do_login(client, kc)
    resp = client.get("/auth/session")
    assert resp.status_code == 200
    assert resp.json()["user"]["roles"] == ["prothetic_user"]
    assert "access_token" not in resp.json()
    second = client.cookies.get("bionicpro_session")
    assert second and second != first
    resp = client.get("/auth/session")
    third = client.cookies.get("bionicpro_session")
    assert third not in (first, second)


def test_old_session_id_is_rejected_after_grace(env):
    client, kc, _, redis = env
    first = do_login(client, kc)
    client.get("/auth/session")
    second = client.cookies.get("bionicpro_session")

    # В окне grace старый id отдает уже выданный новый id без повторной ротации.
    client.cookies.clear()
    client.cookies.set("bionicpro_session", first)
    resp = client.get("/auth/session")
    assert resp.status_code == 200
    assert resp.cookies.get("bionicpro_session") == second

    # После окна grace старый id недействителен.
    import asyncio
    asyncio.run(_expire_markers(redis))
    client.cookies.clear()
    client.cookies.set("bionicpro_session", first)
    resp = client.get("/auth/session")
    assert resp.status_code == 401


async def _expire_markers(redis):
    for key in await redis.keys("bionicpro:session:*"):
        if b"rotated_to" in await redis.get(key):
            await redis.delete(key)


def test_expired_access_token_is_refreshed(env):
    client, kc, router, _ = env
    kc.expires_in = 5  # меньше refresh_margin, обновление при первом запросе
    do_login(client, kc)
    upstream = router.get("http://reports-api:8000/reports").mock(return_value=httpx.Response(200, json={}))
    resp = client.get("/api/reports")
    assert resp.status_code == 200
    assert kc.token_requests[-1]["grant_type"] == "refresh_token"
    assert kc.token_requests[-1]["refresh_token"] == "refresh-1"
    sent = upstream.calls.last.request.headers["authorization"]
    assert sent.startswith("Bearer ")
    assert kc.counter == 2


def test_refresh_failure_ends_session(env):
    client, kc, *_ = env
    kc.expires_in = 5
    do_login(client, kc)
    kc.refresh_error = True
    resp = client.get("/auth/session")
    assert resp.status_code == 401
    assert client.cookies.get("bionicpro_session") is None


def test_proxy_forwards_bearer_and_not_cookie(env):
    client, kc, router, _ = env
    do_login(client, kc)
    upstream = router.get("http://reports-api:8000/reports").mock(
        return_value=httpx.Response(200, json={"ok": True}))
    before = client.cookies.get("bionicpro_session")
    resp = client.get("/api/reports")
    assert resp.status_code == 200 and resp.json() == {"ok": True}
    req = upstream.calls.last.request
    assert req.headers["authorization"].startswith("Bearer eyJ")
    assert "cookie" not in req.headers
    assert client.cookies.get("bionicpro_session") != before


def test_proxy_requires_session(env):
    client, *_ = env
    assert client.get("/api/reports").status_code == 401


def test_logout_checks_origin_and_revokes(env):
    client, kc, _, redis = env
    do_login(client, kc)
    assert client.post("/auth/logout").status_code == 403
    resp = client.post("/auth/logout", headers={"Origin": FRONTEND})
    assert resp.status_code == 204
    assert kc.logout_requests[0]["refresh_token"] == "refresh-1"
    assert client.get("/auth/session").status_code == 401


def test_session_ttl_is_capped_by_refresh_lifetime(env):
    client, kc, _, redis = env
    do_login(client, kc)
    import asyncio

    async def ttls():
        return [await redis.ttl(k) for k in await redis.keys("bionicpro:session:*")]

    for ttl in asyncio.run(ttls()):
        assert 120 < ttl <= 1800


def test_callback_error_returns_to_frontend(env):
    client, kc, *_ = env
    resp = client.get("/auth/callback", params={"error": "access_denied&x=1"})
    assert resp.status_code == 302
    assert resp.headers["location"] == FRONTEND + "/?auth_error=access_denied%26x%3D1"
    assert kc.token_requests == []
