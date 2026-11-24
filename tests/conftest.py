import json
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def defaults() -> dict:
    with open(ROOT / "config" / "defaults.toml", "rb") as f:
        return tomllib.load(f)


@pytest.fixture(scope="session")
def realm() -> dict:
    return json.loads((ROOT / "keycloak" / "realm-export.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def auth_client(realm, defaults) -> dict:
    return next(c for c in realm["clients"] if c["clientId"] == defaults["auth_client"]["client_id"])


@pytest.fixture(scope="session")
def auth_env(compose) -> dict:
    return compose["services"]["bionicpro-auth"]["environment"]


@pytest.fixture(scope="session")
def ldap_provider(realm) -> dict:
    return realm["components"]["org.keycloak.storage.UserStorageProvider"][0]


def flow(realm: dict, alias: str) -> dict:
    return next(f for f in realm["authenticationFlows"] if f["alias"] == alias)
