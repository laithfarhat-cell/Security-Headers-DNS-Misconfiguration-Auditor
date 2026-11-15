"""Regression tests for the GitHub Actions workflow.

The workflow used to fail on every push to ``main`` because the target-resolution
step exited with status 1 when neither ``domains.txt`` nor the ``domains``
dispatch input was available.  A repository without configured domains must stay
green (audit skipped with a notice), and the audit itself must only run when
targets were actually resolved.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "domain-audit.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    with WORKFLOW.open(encoding="utf-8") as fh:
        # PyYAML maps the bare ``on:`` key to ``True`` (YAML 1.1 booleans).
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def triggers(workflow: dict) -> dict:
    return workflow[True]


def _step(job: dict, *, step_id: str | None = None, name: str | None = None) -> dict:
    for step in job["steps"]:
        if step_id is not None and step.get("id") == step_id:
            return step
        if name is not None and step.get("name") == name:
            return step
    raise AssertionError(f"step not found (id={step_id!r}, name={name!r})")


# --------------------------------------------------------------------------------------
# Trigger / job wiring
# --------------------------------------------------------------------------------------
def test_expected_triggers(triggers: dict) -> None:
    assert {"schedule", "workflow_dispatch", "push", "pull_request"} <= set(triggers)
    assert triggers["schedule"][0]["cron"] == "17 4 * * 1"
    assert {"domains", "fail_under", "fail_on_severity"} <= set(triggers["workflow_dispatch"]["inputs"])


def test_jobs_and_gating(workflow: dict) -> None:
    jobs = workflow["jobs"]
    assert set(jobs) == {"quality", "preflight", "audit"}

    # The audit must depend on the preflight that resolves the target list...
    assert set(jobs["audit"]["needs"]) == {"quality", "preflight"}
    # ...and only run when targets were found.
    assert "has_targets" in jobs["audit"]["if"]
    assert jobs["preflight"]["outputs"]["has_targets"]


def test_targets_are_handed_over_via_artifact(workflow: dict) -> None:
    upload = next(
        s for s in workflow["jobs"]["preflight"]["steps"] if "upload-artifact" in str(s.get("uses", ""))
    )
    assert upload["with"]["name"] == "secaudit-targets"
    assert upload["if"] == "steps.resolve.outputs.has_targets == 'true'"

    download = next(
        s for s in workflow["jobs"]["audit"]["steps"] if "download-artifact" in str(s.get("uses", ""))
    )
    assert download["with"]["name"] == upload["with"]["name"]


def test_sarif_upload_has_permission(workflow: dict) -> None:
    assert workflow["permissions"]["security-events"] == "write"
    upload = next(
        s for s in workflow["jobs"]["audit"]["steps"] if "upload-sarif" in str(s.get("uses", ""))
    )
    assert upload["with"]["sarif_file"].endswith(".sarif")
    assert upload["if"].startswith("always()")


# --------------------------------------------------------------------------------------
# The resolve step must never fail the build on an empty target list
# --------------------------------------------------------------------------------------
def test_resolve_step_does_not_fail_on_empty_list(workflow: dict) -> None:
    script = _step(workflow["jobs"]["preflight"], step_id="resolve")["run"]
    assert "exit 1" not in script
    assert "::notice" in script
    assert "has_targets=false" in script


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize(
    ("domains", "expected"),
    [
        ("", []),
        ("   ", []),
        ("example.com", ["example.com"]),
        ("example.com, www.example.com , https://api.example.com/health",
         ["example.com", "www.example.com", "https://api.example.com/health"]),
        ("example.com,example.com", ["example.com"]),
        ("example.com # main site", ["example.com"]),
    ],
)
def test_resolve_script_against_dispatch_input(workflow: dict, tmp_path: Path, domains: str, expected: list[str]) -> None:
    script = _step(workflow["jobs"]["preflight"], step_id="resolve")["run"]
    result = _run_resolve(script, tmp_path, inputs={"INPUT_DOMAINS": domains})
    assert result.returncode == 0, result.stderr

    targets = tmp_path / "targets.txt"
    found = targets.read_text(encoding="utf-8").split() if targets.exists() else []
    assert found == expected

    outputs = (tmp_path / "out.txt").read_text(encoding="utf-8")
    assert f"count={len(expected)}" in outputs
    assert f"has_targets={'true' if expected else 'false'}" in outputs


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_resolve_script_reads_domains_file(workflow: dict, tmp_path: Path) -> None:
    script = _step(workflow["jobs"]["preflight"], step_id="resolve")["run"]
    (tmp_path / "domains.txt").write_text(
        "# leading comment\r\n  example.com  \r\n\r\nwww.example.com # inline\r\nexample.com\r\n",
        encoding="utf-8",
    )
    result = _run_resolve(script, tmp_path, inputs={"INPUT_DOMAINS": ""})
    assert result.returncode == 0, result.stderr
    found = (tmp_path / "targets.txt").read_text(encoding="utf-8").split()
    assert found == ["example.com", "www.example.com"]


def _run_resolve(script: str, cwd: Path, *, inputs: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(cwd),
        "GITHUB_OUTPUT": str(cwd / "out.txt"),
        "GITHUB_STEP_SUMMARY": str(cwd / "summary.md"),
        **inputs,
    }
    return subprocess.run(  # noqa: S603 - fixed shell script, test-only
        ["bash", "-c", script],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
