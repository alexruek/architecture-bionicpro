"""bionicpro-auth: серверная часть входа (BFF) для фронтенда BionicPRO.

Фронтенд не получает токены Keycloak. Сервис выполняет authorization code
flow с PKCE, хранит токены в Redis, выдает браузеру только HttpOnly Secure
cookie с session id и ротирует ее при каждом обращении к защищенным ресурсам.
"""

import logging
import re
import secrets
import time
from contextlib import asynccontextmanager
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from redis.asyncio import Redis

from .config import Settings, load_settings
from .crypto import TokenCipher
from .keycloak import InvalidGrant, KeycloakClient, KeycloakError, user_from_tokens
from .pkce import code_challenge, generate_code_verifier
from .store import Resolved, Session, SessionStore, TokenSet

logger = logging.getLogger("bionicpro-auth")

STATE_COOKIE = "bionicpro_login_state"
IDP_HINT_RE = re.compile(r"^[a-z0-9-]{1,32}$")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
HOP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "content-encoding", "content-length", "set-cookie"}
NO_STORE = {"Cache-Control": "no-store"}


def create_app(settings: Settings | None = None, redis: Redis | None = None,
               http: httpx.AsyncClient | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        own_http = http is None
        app.state.http = http or httpx.AsyncClient(timeout=10.0)
        app.state.redis = redis or Redis.from_url(settings.redis_url)
        app.state.store = SessionStore(
            app.state.redis,
            TokenCipher(settings.token_encryption_key),
            ttl_seconds=settings.session_ttl_seconds,
            grace_seconds=settings.rotation_grace_seconds,
        )
        app.state.keycloak = KeycloakClient(settings, app.state.http)
        yield
        if own_http:
            await app.state.http.aclose()

    app = FastAPI(title="bionicpro-auth", lifespan=lifespan, docs_url=None, redoc_url=None)

    def set_session_cookie(resp: Response, session_id: str, max_age: int) -> None:
        resp.set_cookie(
            settings.cookie_name, session_id, max_age=max_age, path="/",
            httponly=True, secure=True, samesite=settings.cookie_samesite,
        )

    def clear_session_cookie(resp: Response) -> None:
        resp.delete_cookie(settings.cookie_name, path="/", httponly=True, secure=True,
                           samesite=settings.cookie_samesite)

    def unauthorized(detail: str = "not authenticated") -> JSONResponse:
        resp = JSONResponse({"detail": detail}, status_code=401, headers=NO_STORE)
        clear_session_cookie(resp)
        return resp

    def check_origin(request: Request) -> None:
        # Защита от CSRF для изменяющих запросов: cookie SameSite=Lax плюс проверка Origin.
        if request.method not in UNSAFE_METHODS:
            return
        origin = request.headers.get("origin") or ""
        if origin.rstrip("/") != settings.frontend_url:
            raise HTTPException(status_code=403, detail="origin is not allowed")

    async def authenticate(request: Request) -> tuple[Resolved, Session] | None:
        """Проверяет сессию и при необходимости обновляет access_token через refresh_token."""
        session_id = request.cookies.get(settings.cookie_name)
        if not session_id:
            return None
        store: SessionStore = request.app.state.store
        resolved = await store.resolve(session_id)
        if resolved is None:
            return None
        session = resolved.session
        if session.tokens.access_expires_at - time.time() <= settings.refresh_margin_seconds:
            try:
                data = await request.app.state.keycloak.refresh(session.tokens.refresh_token)
            except InvalidGrant:
                await store.delete(resolved.session_id)
                return None
            tokens = TokenSet.from_response(data)
            if not tokens.id_token:
                tokens.id_token = session.tokens.id_token
            session = Session(tokens=tokens, user=session.user, created_at=session.created_at)
            logger.info("access token refreshed for sub=%s", session.user.get("sub"))
        return resolved, session

    async def rotate(request: Request, resolved: Resolved, session: Session, resp: Response) -> None:
        """Перепривязывает токены к новому session id и обновляет cookie (защита от session fixation)."""
        store: SessionStore = request.app.state.store
        if resolved.via_grace:
            # Старый id в коротком окне после ротации: отдаем уже выданный новый id.
            if session is not resolved.session:
                await store.save(resolved.session_id, session)
            set_session_cookie(resp, resolved.session_id, store.ttl_for(session))
            return
        new_id = await store.rotate(resolved, session)
        if new_id is None:
            # Параллельный запрос успел ротировать сессию: берем его результат.
            again = await store.resolve(resolved.session_id)
            if again is None:
                raise HTTPException(status_code=401, detail="session expired")
            new_id = again.session_id
        set_session_cookie(resp, new_id, store.ttl_for(session))

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/auth/login")
    async def login(request: Request, idp: str | None = None) -> Response:
        if idp is not None and not IDP_HINT_RE.match(idp):
            raise HTTPException(status_code=400, detail="invalid idp")
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = generate_code_verifier()
        await request.app.state.store.put_login(
            state, {"code_verifier": verifier, "nonce": nonce}, settings.login_state_ttl_seconds
        )
        url = request.app.state.keycloak.authorization_url(state, nonce, code_challenge(verifier), idp)
        resp = RedirectResponse(url, status_code=302, headers=NO_STORE)
        # state привязан к браузеру, который начал вход (защита от login CSRF).
        resp.set_cookie(STATE_COOKIE, state, max_age=settings.login_state_ttl_seconds, path="/auth/callback",
                        httponly=True, secure=True, samesite="lax")
        return resp

    @app.get("/auth/callback")
    async def callback(request: Request, state: str = "", code: str = "", error: str = "") -> Response:
        if error:
            resp = RedirectResponse(f"{settings.frontend_url}/?auth_error={quote(error[:64])}", status_code=302)
            resp.delete_cookie(STATE_COOKIE, path="/auth/callback")
            return resp
        cookie_state = request.cookies.get(STATE_COOKIE, "")
        if not state or not code or not secrets.compare_digest(state, cookie_state):
            raise HTTPException(status_code=400, detail="invalid state")
        pending = await request.app.state.store.pop_login(state)
        if pending is None:
            raise HTTPException(status_code=400, detail="login expired, start again")
        kc: KeycloakClient = request.app.state.keycloak
        try:
            data = await kc.exchange_code(code, pending["code_verifier"])
            claims = await kc.verify_id_token(data["id_token"], pending["nonce"])
        except KeycloakError as exc:
            logger.warning("code exchange failed: %s", exc)
            raise HTTPException(status_code=401, detail="authentication failed") from exc
        tokens = TokenSet.from_response(data)
        session = Session(tokens=tokens, user=user_from_tokens(claims, tokens.access_token))
        store: SessionStore = request.app.state.store
        session_id = await store.create(session)
        logger.info("session created for sub=%s", session.user["sub"])
        resp = RedirectResponse(f"{settings.frontend_url}/", status_code=302, headers=NO_STORE)
        resp.delete_cookie(STATE_COOKIE, path="/auth/callback")
        set_session_cookie(resp, session_id, store.ttl_for(session))
        return resp

    @app.get("/auth/session")
    async def current_session(request: Request) -> Response:
        auth = await authenticate(request)
        if auth is None:
            return unauthorized()
        resolved, session = auth
        resp = JSONResponse(
            {"authenticated": True, "user": session.user,
             "access_token_expires_at": int(session.tokens.access_expires_at)},
            headers=NO_STORE,
        )
        await rotate(request, resolved, session, resp)
        return resp

    @app.post("/auth/logout")
    async def logout(request: Request) -> Response:
        check_origin(request)
        session_id = request.cookies.get(settings.cookie_name)
        store: SessionStore = request.app.state.store
        if session_id:
            resolved = await store.resolve(session_id)
            if resolved is not None:
                await request.app.state.keycloak.logout(resolved.session.tokens.refresh_token)
                await store.delete(resolved.session_id)
            await store.delete(session_id)
        resp = Response(status_code=204, headers=NO_STORE)
        clear_session_cookie(resp)
        return resp

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def proxy(path: str, request: Request) -> Response:
        """Проксирует запрос к бэкенду, подставляя access_token из сессии."""
        check_origin(request)
        auth = await authenticate(request)
        if auth is None:
            return unauthorized()
        resolved, session = auth
        headers = {"Authorization": f"Bearer {session.tokens.access_token}"}
        for name in ("accept", "content-type"):
            if name in request.headers:
                headers[name] = request.headers[name]
        try:
            upstream = await request.app.state.http.request(
                request.method,
                f"{settings.reports_api_url}/{path}",
                params=request.query_params,
                content=await request.body(),
                headers=headers,
            )
        except httpx.HTTPError:
            upstream = None
        if upstream is None:
            resp: Response = JSONResponse({"detail": "upstream is unavailable"}, status_code=502)
        else:
            out_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in HOP_HEADERS}
            resp = Response(upstream.content, status_code=upstream.status_code, headers=out_headers)
        resp.headers["Cache-Control"] = "no-store"
        await rotate(request, resolved, session, resp)
        return resp

    return app


def build() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return create_app()
