"""Настройки сервиса читаются только из переменных окружения.

Значения по умолчанию для стенда задает docker-compose.yaml, они совпадают
с config/defaults.toml (проверяется тестами).
"""

import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"environment variable {name} is not set")
    return value


def _int(name: str) -> int:
    raw = _required(name)
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"environment variable {name} must be an integer") from exc


@dataclass(frozen=True)
class Settings:
    keycloak_public_url: str
    keycloak_internal_url: str
    keycloak_realm: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scope: str
    frontend_url: str
    redis_url: str
    token_encryption_key: str
    cookie_name: str
    cookie_samesite: str
    session_ttl_seconds: int
    rotation_grace_seconds: int
    refresh_margin_seconds: int
    login_state_ttl_seconds: int
    reports_api_url: str

    @property
    def issuer(self) -> str:
        return f"{self.keycloak_public_url}/realms/{self.keycloak_realm}"

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/auth"

    @property
    def _internal_oidc(self) -> str:
        return f"{self.keycloak_internal_url}/realms/{self.keycloak_realm}/protocol/openid-connect"

    @property
    def token_endpoint(self) -> str:
        return f"{self._internal_oidc}/token"

    @property
    def logout_endpoint(self) -> str:
        return f"{self._internal_oidc}/logout"

    @property
    def jwks_uri(self) -> str:
        return f"{self._internal_oidc}/certs"


def load_settings() -> Settings:
    samesite = _required("SESSION_COOKIE_SAMESITE").lower()
    if samesite not in ("lax", "strict"):
        raise ConfigError("SESSION_COOKIE_SAMESITE must be lax or strict")
    settings = Settings(
        keycloak_public_url=_required("KEYCLOAK_PUBLIC_URL").rstrip("/"),
        keycloak_internal_url=_required("KEYCLOAK_INTERNAL_URL").rstrip("/"),
        keycloak_realm=_required("KEYCLOAK_REALM"),
        client_id=_required("OIDC_CLIENT_ID"),
        client_secret=_required("OIDC_CLIENT_SECRET"),
        redirect_uri=_required("OIDC_REDIRECT_URI"),
        scope=_required("OIDC_SCOPE"),
        frontend_url=_required("FRONTEND_URL").rstrip("/"),
        redis_url=_required("REDIS_URL"),
        token_encryption_key=os.environ.get("TOKEN_ENCRYPTION_KEY", "").strip(),
        cookie_name=_required("SESSION_COOKIE_NAME"),
        cookie_samesite=samesite,
        session_ttl_seconds=_int("SESSION_TTL_SECONDS"),
        rotation_grace_seconds=_int("SESSION_ROTATION_GRACE_SECONDS"),
        refresh_margin_seconds=_int("ACCESS_TOKEN_REFRESH_MARGIN_SECONDS"),
        login_state_ttl_seconds=_int("LOGIN_STATE_TTL_SECONDS"),
        reports_api_url=_required("REPORTS_API_URL").rstrip("/"),
    )
    if settings.rotation_grace_seconds >= settings.session_ttl_seconds:
        raise ConfigError("SESSION_ROTATION_GRACE_SECONDS must be less than SESSION_TTL_SECONDS")
    return settings
