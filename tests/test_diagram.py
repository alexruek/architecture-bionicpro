"""Визуальные соглашения C4-диаграммы проверяются по легенде, а не только глазами."""

import re
import xml.etree.ElementTree as ET

import pytest

from conftest import ROOT

DIAGRAM = ROOT / "diagrams" / "bionicpro-c4-security.drawio"
STATUS_STROKES = ("strokeColor=#E8590C;strokeWidth=3;", "strokeColor=#F59F00;strokeWidth=3;")


@pytest.fixture(scope="module")
def objects():
    tree = ET.parse(DIAGRAM)
    # Схема хранится несжатой: внутри diagram сразу mxGraphModel.
    assert tree.getroot().find("diagram/mxGraphModel") is not None
    return tree.getroot().findall(".//object")


def _style(obj) -> str:
    return obj.find("mxCell").get("style")


def _base(style: str) -> str:
    for marker in STATUS_STROKES:
        style = style.replace(marker, "")
    return style


def _legend(objects, **attrs):
    for obj in objects:
        if obj.get("legend") == "1" and obj.get("c4Status") is None and all(
                obj.get(k) == v for k, v in attrs.items()):
            return obj
    raise AssertionError(f"legend has no sample for {attrs}")


def test_text_style_rules():
    text = DIAGRAM.read_text(encoding="utf-8")
    assert "\u0451" not in text and "\u0401" not in text
    assert "\u2014" not in text
    assert "&lt;b&gt;" not in text and "<b>" not in text
    assert "fontStyle=1" not in text


def test_elements_follow_legend(objects):
    for obj in objects:
        c4type = obj.get("c4Type")
        if obj.get("legend") == "1" or c4type in (None, "Boundary"):
            continue
        sample = _legend(objects, c4Type=c4type)
        assert _base(_style(obj)) == _base(_style(sample)), obj.get("id")


def test_status_markers_follow_legend(objects):
    marker = {
        "new": "strokeColor=#E8590C;strokeWidth=3;",
        "changed": "strokeColor=#F59F00;strokeWidth=3;",
    }
    for status, stroke in marker.items():
        sample = next(o for o in objects if o.get("legend") == "1" and o.get("c4Status") == status)
        assert stroke in _style(sample)
    for obj in objects:
        if obj.get("c4Type") in (None, "Boundary"):
            continue
        status = obj.get("c4Status")
        style = _style(obj)
        if status:
            assert marker[status] in style, obj.get("id")
        else:
            assert not any(m in style for m in marker.values()), obj.get("id")


def test_edges_follow_legend(objects):
    ids = {o.get("id") for o in objects} | {c.get("id") for c in ET.parse(DIAGRAM).getroot().iter("mxCell")}
    edges = [o for o in objects if o.find("mxCell").get("edge") == "1"]
    used = set()
    for obj in edges:
        kind = obj.get("c4Kind")
        assert kind in ("sync", "redirect"), obj.get("id")
        cell = obj.find("mxCell")
        assert cell.get("source") in ids and cell.get("target") in ids, obj.get("id")
        sample = _style(_legend(objects, c4Kind=kind))
        strip = lambda s: re.sub(r"(exit|entry)(X|Y|Dx|Dy)=[^;]+;", "", s)
        assert strip(_style(obj)) == strip(sample), obj.get("id")
        if obj.get("legend") != "1":
            used.add(kind)
    assert used == {"sync", "redirect"}


def test_required_containers_present(objects):
    labels = " ".join(o.get("label", "") for o in objects)
    for name in ("bionicpro-auth", "Keycloak", "Redis", "OpenLDAP", "Яндекс ID", "IdP других стран"):
        assert name in labels, name
