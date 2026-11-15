"""Configuration handling and data-file integrity tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.config import (
    deep_merge,
    default_config,
    get,
    load_config,
    normalise_nameservers,
    resource_file,
    with_overrides,
)


class TestConfig:
    def test_defaults_load(self) -> None:
        config = default_config()
        assert config["scan"]["concurrency"] == 10
        assert config["scoring"]["category_weights"]["http_headers"] == 45
        assert config["dns"]["spf_lookup_limit"] == 10

    def test_deep_merge_does_not_mutate(self) -> None:
        base = {"a": {"b": 1, "c": 2}, "d": [1, 2]}
        overlay = {"a": {"c": 3}, "d": [9]}
        merged = deep_merge(base, overlay)
        assert merged["a"] == {"b": 1, "c": 3}
        assert merged["d"] == [9]
        assert base["a"]["c"] == 2

    def test_load_config_merges_file(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom.yaml"
        custom.write_text(
            "scan:\n  concurrency: 3\nscoring:\n  ignore_checks:\n    - dns.mta_sts\n"
        )
        config = load_config(custom)
        assert config["scan"]["concurrency"] == 3
        assert config["scan"]["timeout"] == 10.0  # default preserved
        assert config["scoring"]["ignore_checks"] == ["dns.mta_sts"]

    def test_load_config_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nope.yaml")

    def test_load_config_invalid_yaml(self, tmp_path: Path) -> None:
        broken = tmp_path / "broken.yaml"
        broken.write_text("- just\n- a list\n")
        with pytest.raises(ValueError):
            load_config(broken)

    def test_dotted_get(self) -> None:
        config = default_config()
        assert get(config, "scan.timeout") == 10.0
        assert get(config, "scan.missing", "fallback") == "fallback"
        assert get(config, "nope.deep.key", None) is None

    def test_with_overrides_skips_none(self) -> None:
        config = with_overrides(default_config(), {"scan.concurrency": 5, "scan.timeout": None})
        assert config["scan"]["concurrency"] == 5
        assert config["scan"]["timeout"] == 10.0

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (["1.1.1.1"], ["1.1.1.1"]),
            (["1.1.1.1,8.8.8.8"], ["1.1.1.1", "8.8.8.8"]),
            (["1.1.1.1:5353"], ["1.1.1.1@5353"]),
            (["[2606:4700:4700::1111]:53"], ["2606:4700:4700::1111@53"]),
            (["2606:4700:4700::1111"], ["2606:4700:4700::1111"]),
            ([], []),
        ],
    )
    def test_normalise_nameservers(self, raw: list[str], expected: list[str]) -> None:
        assert normalise_nameservers(raw) == expected


class TestDataFiles:
    def test_dangling_cname_database_is_valid(self) -> None:
        path = resource_file("data", "dangling_cnames.json")
        assert path is not None and path.is_file()
        data = json.loads(path.read_text(encoding="utf-8"))
        services = data["services"]
        assert len(services) >= 20

        allowed_severities = {"critical", "high", "medium", "low"}
        suffixes: list[str] = []
        for service in services:
            assert service["service"]
            assert service["provider"]
            assert service["cname_suffixes"], service["service"]
            assert service["severity"] in allowed_severities, service["service"]
            assert service.get("claim_url", "").startswith("https://"), service["service"]
            for suffix in service["cname_suffixes"]:
                assert not suffix.startswith("."), suffix
                assert not suffix.endswith("."), suffix
                suffixes.append(suffix.lower())
        assert len(suffixes) == len(set(suffixes)), "duplicate CNAME suffix in the database"

    def test_default_yaml_is_packaged(self) -> None:
        path = resource_file("config", "default.yaml")
        assert path is not None and path.is_file()
        assert "category_weights" in path.read_text(encoding="utf-8")
