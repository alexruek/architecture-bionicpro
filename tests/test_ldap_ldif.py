"""ldif представительства согласован сам с собой и с ролями realm."""

from conftest import ROOT


def _entries() -> list[dict]:
    entries, current = [], {}
    for line in (ROOT / "ldap" / "config.ldif").read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        if not line.strip():
            if current:
                entries.append(current)
            current = {}
            continue
        key, value = line.split(":", 1)
        current.setdefault(key.strip(), []).append(value.strip())
    if current:
        entries.append(current)
    return entries


def test_rdn_matches_uid():
    for e in _entries():
        dn = e["dn"][0]
        if dn.startswith("uid="):
            assert dn.split(",")[0][4:] in e["uid"], dn


def test_group_members_exist():
    entries = _entries()
    dns = {e["dn"][0] for e in entries}
    for e in entries:
        for member in e.get("member", []):
            assert member in dns, member


def test_ldap_groups_are_realm_roles(realm, defaults):
    roles = {r["name"] for r in realm["roles"]["realm"]}
    for e in _entries():
        if e["dn"][0].endswith(defaults["ldap"]["groups_dn"]) and "cn" in e:
            assert e["cn"][0] in roles
