"""Configuration loading and resource discovery.

The YAML in ``config/default.yaml`` is the single source of truth for defaults;
it ships inside the wheel so ``pip install .`` works without the repository.
CLI flags always win over configuration file values.
"""

from __future__ import annotations

import copy
import importlib.resources
import logging
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_packaged(package: str, filename: str) -> str | None:
    """Read a text resource shipped in a package (wheel) or the source tree."""
    try:
        resource = importlib.resources.files(package).joinpath(filename)
        if resource.is_file():
            return resource.read_text(encoding="utf-8")
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        pass
    candidate = _REPO_ROOT / package / filename
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8")
    return None


def resource_file(package: str, filename: str) -> Path | None:
    """Best-effort filesystem path for a packaged resource."""
    try:
        resource = importlib.resources.files(package).joinpath(filename)
        path = Path(str(resource))
        if path.is_file():
            return path
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        pass
    candidate = _REPO_ROOT / package / filename
    return candidate if candidate.is_file() else None


@lru_cache(maxsize=1)
def default_config() -> dict[str, Any]:
    """Return the bundled default configuration as a plain dict."""
    raw = _read_packaged("config", "default.yaml")
    if raw is None:  # pragma: no cover - packaging safety net
        log.warning("config/default.yaml not found, using built-in defaults")
        return {
            "version": 1,
            "scan": {"concurrency": 10, "timeout": 10.0, "max_redirects": 10},
            "scoring": {"category_weights": {"http_headers": 45, "tls": 25, "dns_email": 30}},
            "http": {"hsts_min_max_age": 31536000, "check_security_txt": True, "check_cookies": True},
            "dns": {"nameservers": [], "spf_lookup_limit": 10, "fingerprints_file": "dangling_cnames.json"},
            "reporting": {"remediation_min_severity": "HIGH", "include_passed_in_json": True},
        }
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):  # pragma: no cover - defensive
        raise ValueError("config/default.yaml must contain a mapping")
    return data


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base`` (lists replaced)."""
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load the default configuration and merge an optional user file on top."""
    config = copy.deepcopy(default_config())
    if path is None:
        return config
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise FileNotFoundError(f"configuration file not found: {file_path}")
    raw = yaml.safe_load(file_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"configuration file {file_path} must contain a YAML mapping")
    if raw.get("version") not in (None, 1):
        log.warning("Configuration version %r is newer than this build understands", raw["version"])
    return deep_merge(config, raw)


def get(config: dict[str, Any], dotted: str, default: Any = None) -> Any:
    """Read a nested value using a dotted path (``scan.timeout``)."""
    node: Any = config
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def with_overrides(config: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Apply dotted-path overrides (only non-``None`` values)."""
    result = copy.deepcopy(config)
    for dotted, value in overrides.items():
        if value is None:
            continue
        parts = dotted.split(".")
        node = result
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return result


def normalise_nameservers(values: Iterable[str] | None) -> list[str]:
    """Accept ``1.1.1.1``, ``1.1.1.1:53``, ``dns.google`` and comma separated lists."""
    out: list[str] = []
    for raw in values or []:
        for chunk in str(raw).replace(",", " ").split():
            chunk = chunk.strip()
            if not chunk:
                continue
            if chunk.startswith("["):  # [2606:4700::1111]:53
                host, _, port = chunk.partition("]")
                host = host.lstrip("[")
                port = port.lstrip(":")
            elif chunk.count(":") == 1:
                host, _, port = chunk.partition(":")
            else:
                host, port = chunk, ""
            if port:
                out.append(f"{host}@{port}")
            else:
                out.append(host)
    return out

