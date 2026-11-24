"""Настройки realm совпадают с config/defaults.toml и требованиями задания 1."""

from conftest import ROOT, flow


def test_token_lifetimes(realm, defaults):
    kc = defaults["keycloak"]
    assert realm["realm"] == kc["realm"]
    assert realm["accessTokenLifespan"] == kc["access_token_lifespan_seconds"]
    assert realm["accessTokenLifespan"] <= 120
    assert realm["ssoSessionIdleTimeout"] == kc["sso_session_idle_timeout_seconds"]
    assert realm["ssoSessionMaxLifespan"] == kc["sso_session_max_lifespan_seconds"]
    assert realm["revokeRefreshToken"] == kc["revoke_refresh_token"]


def test_auth_client_uses_pkce_and_code_flow_only(auth_client, defaults):
    ac = defaults["auth_client"]
    assert auth_client["attributes"]["pkce.code.challenge.method"] == defaults["pkce"]["code_challenge_method"]
    assert auth_client["attributes"]["use.refresh.tokens"] == "true"
    assert auth_client["publicClient"] is False
    assert auth_client["standardFlowEnabled"] is True
    assert auth_client["implicitFlowEnabled"] is False
    assert auth_client["directAccessGrantsEnabled"] is False
    assert auth_client["redirectUris"] == [ac["redirect_uri"]]
    assert auth_client["consentRequired"] is ac["consent_required"]
    # Без явного fullScopeAllowed Keycloak при consentRequired убирает роли из токена.
    assert auth_client["fullScopeAllowed"] is True


def test_no_client_hands_tokens_to_browser(realm):
    for client in realm["clients"]:
        if client.get("bearerOnly"):
            continue
        assert client.get("publicClient") is False, client["clientId"]
        assert client.get("implicitFlowEnabled") is False, client["clientId"]
        assert client.get("directAccessGrantsEnabled") is False, client["clientId"]


def test_otp_is_mandatory_in_browser_flow(realm, defaults):
    kc = defaults["keycloak"]
    assert realm["browserFlow"] == kc["browser_flow"]
    browser = flow(realm, kc["browser_flow"])
    forms_alias = next(e["flowAlias"] for e in browser["authenticationExecutions"] if e.get("flowAlias"))
    forms = {e["authenticator"]: e["requirement"] for e in flow(realm, forms_alias)["authenticationExecutions"]}
    assert forms == {"auth-username-password-form": "REQUIRED", "auth-otp-form": "REQUIRED"}
    redirector = [e for e in browser["authenticationExecutions"]
                  if e.get("authenticator") == "identity-provider-redirector"]
    assert redirector and redirector[0]["requirement"] == "ALTERNATIVE"


def test_otp_policy(realm, defaults):
    otp = defaults["otp"]
    assert realm["otpPolicyType"] == otp["type"]
    assert realm["otpPolicyAlgorithm"] == otp["algorithm"]
    assert realm["otpPolicyDigits"] == otp["digits"]
    assert realm["otpPolicyPeriod"] == otp["period_seconds"]
    assert "totpAppGoogleName" in realm["otpSupportedApplications"]
    assert "totpAppFreeOTPName" in realm["otpSupportedApplications"]


def test_all_flow_bindings_exist(realm):
    aliases = {f["alias"] for f in realm["authenticationFlows"]}
    for key in ("browserFlow", "registrationFlow", "directGrantFlow", "resetCredentialsFlow",
                "clientAuthenticationFlow", "dockerAuthenticationFlow"):
        assert realm[key] in aliases, key
    for f in realm["authenticationFlows"]:
        for e in f["authenticationExecutions"]:
            if e.get("flowAlias"):
                assert e["flowAlias"] in aliases


def test_yandex_identity_provider(realm, defaults):
    ya = defaults["yandex"]
    idp = next(i for i in realm["identityProviders"] if i["alias"] == ya["alias"])
    assert idp["providerId"] == "yandex"
    assert idp["config"]["defaultScope"] == ya["default_scope"]
    # Секреты не хранятся в репозитории, Keycloak подставляет их из окружения.
    assert idp["config"]["clientId"] == "${YANDEX_CLIENT_ID}"
    assert idp["config"]["clientSecret"] == "${YANDEX_CLIENT_SECRET}"
    assert idp["postBrokerLoginFlowAlias"] == defaults["keycloak"]["post_broker_login_flow"]
    post = flow(realm, idp["postBrokerLoginFlowAlias"])
    assert [(e["authenticator"], e["requirement"]) for e in post["authenticationExecutions"]] == [
        ("auth-otp-form", "REQUIRED")]
    mappers = [m for m in realm["identityProviderMappers"] if m["identityProviderAlias"] == ya["alias"]]
    assert {m["config"]["jsonField"] for m in mappers} >= {"id", "login"}


def test_yandex_provider_version_in_dockerfile(defaults):
    dockerfile = (ROOT / "keycloak" / "Dockerfile").read_text(encoding="utf-8")
    assert f"FROM {defaults['keycloak']['image']}\n" in dockerfile
    assert f"ARG RUSSIAN_PROVIDERS_VERSION={defaults['yandex']['providers_version']}\n" in dockerfile


def test_ldap_federation(ldap_provider, defaults):
    ld = defaults["ldap"]
    cfg = ldap_provider["config"]
    assert cfg["connectionUrl"] == [ld["connection_url"]]
    assert cfg["usersDn"] == [ld["users_dn"]]
    assert cfg["bindDn"] == [ld["bind_dn"]]
    assert cfg["editMode"] == ["READ_ONLY"]
    # Персональные данные представительства не копируются в БД Keycloak.
    assert cfg["importEnabled"] == ["false"]
    roles = next(m for m in ldap_provider["subComponents"]["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"]
                 if m["providerId"] == "role-ldap-mapper")
    assert roles["config"]["roles.dn"] == [ld["groups_dn"]]
    assert roles["config"]["use.realm.roles.mapping"] == ["true"]
