"""
CI/CD Pipeline Security Scanner (GitHub Actions)

Controls evaluated:
1. Overly broad permissions (write-all or admin)
2. Unpinned action versions (not using SHA)
3. Secret exposure in run steps (echo ${{ secrets.* }})
4. pull_request_target with untrusted code checkout
5. Debug flags exposing sensitive info
6. Missing job timeout (resource abuse risk)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
_WORKFLOW_PATH = _EXAMPLES_DIR / "github_actions_workflow.yml"

_SHA_PATTERN = re.compile(r"@[0-9a-f]{40}$")
_SECRET_ECHO_PATTERN = re.compile(r"echo\s+.*\$\{\{\s*secrets\.", re.IGNORECASE)
_WRITE_ALL_PERMS = {"write-all", "admin"}


def _finding(check_id, resource, finding, severity, recommendation, nist_csf_function):
    return {
        "scanner": "cicd",
        "check_id": check_id,
        "resource": resource,
        "finding": finding,
        "severity": severity,
        "recommendation": recommendation,
        "nist_csf_function": nist_csf_function,
    }


def _load_workflow(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _iter_steps(jobs: dict) -> list[tuple[str, dict]]:
    result = []
    for job_name, job_data in (jobs or {}).items():
        if not isinstance(job_data, dict):
            continue
        for step in job_data.get("steps", []) or []:
            if isinstance(step, dict):
                result.append((job_name, step))
    return result


def _check_cicd_001_broad_permissions(workflow: dict) -> list[dict]:
    findings = []

    def _eval_perms(perms: Any, label: str) -> None:
        if isinstance(perms, str) and perms in _WRITE_ALL_PERMS:
            findings.append(_finding(
                "CICD-001", label,
                f"Workflow permissions set to '{perms}'. Grants write access to all repository scopes.",
                "HIGH",
                "Replace 'permissions: write-all' with explicit minimal permissions per-job.",
                "PROTECT",
            ))
        elif isinstance(perms, dict):
            broad_scopes = {"contents", "packages", "deployments", "id-token", "security-events"}
            for scope, level in perms.items():
                if level in ("write", "admin") and scope in broad_scopes:
                    findings.append(_finding(
                        "CICD-001", f"{label}/permissions:{scope}",
                        f"Permission scope '{scope}: {level}' grants broad write access.",
                        "MEDIUM",
                        f"Restrict '{scope}' to 'read' unless write is strictly required.",
                        "PROTECT",
                    ))

    _eval_perms(workflow.get("permissions"), "workflow:permissions")
    for job_name, job_data in (workflow.get("jobs", {}) or {}).items():
        if isinstance(job_data, dict):
            _eval_perms(job_data.get("permissions"), f"job:{job_name}/permissions")
    return findings


def _check_cicd_002_unpinned_actions(workflow: dict) -> list[dict]:
    findings = []
    for job_name, step in _iter_steps(workflow.get("jobs", {})):
        uses = step.get("uses", "")
        if not uses:
            continue
        if not _SHA_PATTERN.search(uses):
            findings.append(_finding(
                "CICD-002",
                f"job:{job_name}/step:{step.get('name', uses)}",
                f"Action '{uses}' is not pinned to a full commit SHA. Tags are mutable and can be "
                "updated to malicious commits (supply-chain attack vector).",
                "HIGH",
                f"Pin to a full SHA: 'uses: {uses.split('@')[0]}@<40-char-sha>'. "
                "Use Dependabot or pin-github-action to automate pinning.",
                "PROTECT",
            ))
    return findings


def _check_cicd_003_secret_exposure(workflow: dict) -> list[dict]:
    findings = []
    for job_name, step in _iter_steps(workflow.get("jobs", {})):
        run_block = step.get("run", "")
        if not run_block:
            continue
        for line in str(run_block).splitlines():
            if _SECRET_ECHO_PATTERN.search(line):
                findings.append(_finding(
                    "CICD-003",
                    f"job:{job_name}/step:{step.get('name', '?')}",
                    f"Step '{step.get('name', '?')}' echoes a secret to the runner log. "
                    "Even with log masking, secrets may leak via encoding tricks.",
                    "CRITICAL",
                    "Remove debug echo statements referencing ${{ secrets.* }}. "
                    "Use '::add-mask::' only for dynamic values if absolutely needed.",
                    "DETECT",
                ))
                break
    return findings


def _check_cicd_004_pull_request_target(workflow: dict) -> list[dict]:
    findings = []
    triggers = workflow.get("on", {}) or {}
    if "pull_request_target" not in triggers:
        return findings
    for job_name, step in _iter_steps(workflow.get("jobs", {})):
        uses = step.get("uses", "")
        with_params = step.get("with", {}) or {}
        checkout_ref = str(with_params.get("ref", ""))
        if "checkout" in uses and "pull_request" in checkout_ref:
            findings.append(_finding(
                "CICD-004",
                f"job:{job_name}/step:{step.get('name', '?')}",
                "Workflow uses 'pull_request_target' (runs with repo secrets and write permission) "
                "and checks out the PR's HEAD ref from a potentially untrusted fork. "
                "An attacker can inject and execute arbitrary code with access to secrets.",
                "CRITICAL",
                "Do not check out untrusted PR code in pull_request_target workflows. "
                "Use 'pull_request' trigger for PR-triggered builds (read-only, no write secrets).",
                "PROTECT",
            ))
    return findings


def _check_cicd_005_debug_flags(workflow: dict) -> list[dict]:
    findings = []
    _debug_vars = {"ACTIONS_RUNNER_DEBUG", "ACTIONS_STEP_DEBUG"}

    def _scan_env(env: dict | None, label: str) -> None:
        if not isinstance(env, dict):
            return
        for var, value in env.items():
            if var in _debug_vars and str(value).lower() in ("true", "1", "yes"):
                findings.append(_finding(
                    "CICD-005",
                    f"{label}/env:{var}",
                    f"Debug flag '{var}' is permanently enabled. Debug mode may dump "
                    "environment variables and secret values to the run log.",
                    "MEDIUM",
                    f"Remove '{var}' from the YAML. Enable via repository secret on a per-run basis.",
                    "DETECT",
                ))

    _scan_env(workflow.get("env"), "workflow")
    for job_name, job_data in (workflow.get("jobs", {}) or {}).items():
        if isinstance(job_data, dict):
            _scan_env(job_data.get("env"), f"job:{job_name}")
    return findings


def _check_cicd_006_missing_timeout(workflow: dict) -> list[dict]:
    findings = []
    for job_name, job_data in (workflow.get("jobs", {}) or {}).items():
        if not isinstance(job_data, dict):
            continue
        if "timeout-minutes" not in job_data:
            findings.append(_finding(
                "CICD-006",
                f"job:{job_name}",
                f"Job '{job_name}' has no 'timeout-minutes'. A hung job consumes runner "
                "minutes until GitHub's 6-hour default — a cost/resource risk.",
                "LOW",
                "Add 'timeout-minutes: <N>' to each job. Most jobs should complete in < 30 min.",
                "PROTECT",
            ))
    return findings


def run() -> list[dict]:
    """Execute all 6 CI/CD checks and return a flat list of findings."""
    workflow = _load_workflow(_WORKFLOW_PATH)
    findings: list[dict] = []
    findings.extend(_check_cicd_001_broad_permissions(workflow))
    findings.extend(_check_cicd_002_unpinned_actions(workflow))
    findings.extend(_check_cicd_003_secret_exposure(workflow))
    findings.extend(_check_cicd_004_pull_request_target(workflow))
    findings.extend(_check_cicd_005_debug_flags(workflow))
    findings.extend(_check_cicd_006_missing_timeout(workflow))
    return findings


if __name__ == "__main__":
    for f in run():
        print(f)
