"""Оформление текстов и кода в репозитории."""

import subprocess

from conftest import ROOT

TEXT_SUFFIXES = {".md", ".py", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".conf", ".drawio", ".ldif", ".txt", ".ini", ""}


def _tracked_files():
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for name in out.splitlines():
        path = ROOT / name
        if path.is_file() and path.suffix in TEXT_SUFFIXES and path.name != "package-lock.json":
            yield path


def test_no_yo_and_long_dash():
    for path in _tracked_files():
        text = path.read_text(encoding="utf-8")
        assert "\u0451" not in text and "\u0401" not in text, path.relative_to(ROOT)
        assert "\u2014" not in text, path.relative_to(ROOT)


def test_no_bold_in_markdown():
    for path in _tracked_files():
        if path.suffix == ".md":
            text = path.read_text(encoding="utf-8")
            assert "*" * 2 not in text and "_" * 2 not in text.replace("__init__", ""), path.relative_to(ROOT)


def test_no_absolute_local_paths():
    for path in _tracked_files():
        text = path.read_text(encoding="utf-8")
        for marker in ("/" + "home/", "/" + "Users/", "C:" + "\\"):
            assert marker not in text, path.relative_to(ROOT)
