"""Интеграция с Keycloak: authorization code + PKCE, refresh, logout, проверка id_token."""

import time
from urllib.parse import urlencode

import httpx
import jwt

from .config import Settings
from .pkce import CODE_CHALLENGE_METHOD


class KeycloakError(Exception):
    pass


class InvalidGrant(KeycloakError):
    """Keycloak отклонил code или refresh_token: сессию нужно завершить."""


class KeycloakClient:
    def __init__(self, settings: Settings, http: httpx.AsyncClient):
        self._s = settings
        self._http = http
        self._jwks: jwt.PyJWKSet | None = None
        self._jwks_loaded_at = 0.0

    def authorization_url(self, state: str, nonce: str, challenge: str, idp_hint: str | None) -> str:
        params = {
            "response_type": "code",
            "client_id": self._s.client_id,
            "redirect_uri": self._s.redirect_uri,
            "scope": self._s.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": CODE_CHALLENGE_METHOD,
        }
        if idp_hint:
            params["kc_idp_hint"] = idp_hint
        return f"{self._s.authorization_endpoint}?{urlencode(params)}"

    async def _token_request(self, form: dict) -> dict:
        form = {**form, "client_id": self._s.client_id, "client_secret": self._s.client_secret}
        try:
            resp = await self._http.post(self._s.token_endpoint, data=form)
        except httpx.HTTPError as exc:
            raise KeycloakError(f"token endpoint is unavailable: {exc}") from exc
        if resp.status_code == 400 and resp.json().get("error") == "invalid_grant":
            raise InvalidGrant(resp.json().get("error_description", "invalid_grant"))
        if resp.status_code != 200:
            raise KeycloakError(f"token endpoint returned {resp.status_code}")
        return resp.json()

    async def exchange_code(self, code: str, code_verifier: str) -> dict:
        return await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._s.redirect_uri,
                "code_verifier": code_verifier,
            }
        )

    async def refresh(self, refresh_token: str) -> dict:
        return await self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})

    async def logout(self, refresh_token: str) -> None:
        form = {
            "client_id": self._s.client_id,
            "client_secret": self._s.client_secret,
            "refresh_token": refresh_token,
        }
        try:
            await self._http.post(self._s.logout_endpoint, data=form)
        except httpx.HTTPError:
            # Локальная сессия удаляется в любом случае.
            pass

    async def _load_jwks(self, force: bool = False) -> jwt.PyJWKSet:
        if self._jwks is None or force or time.time() - self._jwks_loaded_at > 3600:
            resp = await self._http.get(self._s.jwks_uri)
            resp.raise_for_status()
            # В JWKS Keycloak есть и ключ шифрования RSA-OAEP, берем только ключи подписи.
            keys = [k for k in resp.json()["keys"] if k.get("use", "sig") == "sig"]
            self._jwks = jwt.PyJWKSet.from_dict({"keys": keys})
            self._jwks_loaded_at = time.time()
        return self._jwks

    async def _signing_key(self, token: str) -> jwt.PyJWK:
        kid = jwt.get_unverified_header(token).get("kid")
        for force in (False, True):
            jwks = await self._load_jwks(force=force)
            for key in jwks.keys:
                if key.key_id == kid:
                    return key
        raise KeycloakError("signing key for id_token not found")

    async def verify_id_token(self, id_token: str, nonce: str) -> dict:
        key = await self._signing_key(id_token)
        try:
            claims = jwt.decode(
                id_token,
                key=key.key,
                algorithms=["RS256"],
                audience=self._s.client_id,
                issuer=self._s.issuer,
                leeway=30,
            )
        except jwt.PyJWTError as exc:
            raise KeycloakError(f"id_token is invalid: {exc}") from exc
        if claims.get("nonce") != nonce:
            raise KeycloakError("id_token nonce mismatch")
        return claims


def user_from_tokens(id_claims: dict, access_token: str) -> dict:
    # access_token получен напрямую от Keycloak по серверному каналу,
    # подпись id_token уже проверена, роли читаем без повторной проверки.
    access_claims = jwt.decode(access_token, options={"verify_signature": False})
    return {
        "sub": id_claims["sub"],
        "username": id_claims.get("preferred_username"),
        "email": id_claims.get("email"),
        "name": id_claims.get("name"),
        "roles": sorted(access_claims.get("realm_access", {}).get("roles", [])),
        "identity_provider": access_claims.get("identity_provider") or id_claims.get("identity_provider"),
    }
