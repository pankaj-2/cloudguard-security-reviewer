"""
GCP IAM Security Scanner

GCP controls evaluated:
1. allUsers / allAuthenticatedUsers IAM bindings (roles/owner or any)
2. Human users assigned Owner role at project level
3. Exported user-managed service account keys
4. Service account keys not rotated in >90 days
5. Service accounts not using Workload Identity Federation
6. Test/temp service accounts in production
7. Editor role assigned at project scope
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths — resolves relative to this file so the scanner works from any cwd
# ---------------------------------------------------------------------------
_EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
_IAM_POLICY_PATH = _EXAMPLES_DIR / "gcp_iam_policy.json"
_SERVICE_ACCOUNTS_PATH = _EXAMPLES_DIR / "gcp_service_accounts.json"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
_STALE_KEY_DAYS = 90
_TEST_TEMP_PATTERNS = re.compile(r"\b(test|temp|tmp|demo|scratch|poc|dev-only)\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
def _finding(
    check_id: str,
    resource: str,
    finding: str,
    severity: str,
    recommendation: str,
    nist_csf_function: str,
) -> dict[str, str]:
    return {
        "scanner": "gcp_iam",
        "check_id": check_id,
        "resource": resource,
        "finding": finding,
        "severity": severity,
        "recommendation": recommendation,
        "nist_csf_function": nist_csf_function,
    }


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _key_age_days(valid_after_time: str) -> int:
    """Return the number of days since the key was created."""
    created = datetime.fromisoformat(valid_after_time.replace("Z", "+00:00"))
    now = datetime.now(tz=timezone.utc)
    return (now - created).days


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def _check_001_public_iam_bindings(bindings: list[dict]) -> list[dict]:
    """GCP-001: allUsers / allAuthenticatedUsers present in any binding."""
    findings: list[dict] = []
    for binding in bindings:
        role = binding.get("role", "")
        members = binding.get("members", [])
        for member in members:
            if member in _PUBLIC_MEMBERS:
                severity = "CRITICAL" if "owner" in role.lower() else "HIGH"
                findings.append(
                    _finding(
                        check_id="GCP-001",
                        resource=f"{role} → {member}",
                        finding=(
                            f"Public member '{member}' is granted '{role}'. "
                            "This exposes the resource to the entire internet or all Google accounts."
                        ),
                        severity=severity,
                        recommendation=(
                            "Remove 'allUsers' and 'allAuthenticatedUsers' from all IAM bindings. "
                            "Replace with specific user, service-account, or group principals."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _check_002_human_owner(bindings: list[dict]) -> list[dict]:
    """GCP-002: Human user accounts assigned roles/owner at project level."""
    findings: list[dict] = []
    for binding in bindings:
        role = binding.get("role", "")
        if role != "roles/owner":
            continue
        for member in binding.get("members", []):
            if member.startswith("user:"):
                findings.append(
                    _finding(
                        check_id="GCP-002",
                        resource=f"{role} → {member}",
                        finding=(
                            f"Human user '{member}' holds the Owner role at project scope. "
                            "Owner grants unrestricted access to all resources and IAM policies."
                        ),
                        severity="HIGH",
                        recommendation=(
                            "Remove Owner from human users. "
                            "Grant least-privilege roles such as roles/editor or specific resource roles. "
                            "Use groups rather than individual accounts for administrative access."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _check_003_exported_sa_keys(accounts: list[dict]) -> list[dict]:
    """GCP-003: Service accounts with user-managed (exported) keys."""
    findings: list[dict] = []
    for account in accounts:
        email = account.get("email", "unknown")
        for key in account.get("keys", []):
            if key.get("keyType") == "USER_MANAGED":
                findings.append(
                    _finding(
                        check_id="GCP-003",
                        resource=f"serviceAccount:{email} / key:{key.get('name', '').split('/')[-1]}",
                        finding=(
                            "This service account has a user-managed (exported) key. "
                            "Exported keys leave GCP's security perimeter and increase credential theft risk."
                        ),
                        severity="HIGH",
                        recommendation=(
                            "Delete the exported key and migrate to Workload Identity Federation. "
                            "If keys are unavoidable, store them in Secret Manager with rotation enforced."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _check_004_stale_sa_keys(accounts: list[dict]) -> list[dict]:
    """GCP-004: Service account keys older than 90 days."""
    findings: list[dict] = []
    for account in accounts:
        email = account.get("email", "unknown")
        for key in account.get("keys", []):
            if key.get("keyType") != "USER_MANAGED":
                continue
            valid_after = key.get("validAfterTime", "")
            if not valid_after:
                continue
            age_days = _key_age_days(valid_after)
            if age_days > _STALE_KEY_DAYS:
                findings.append(
                    _finding(
                        check_id="GCP-004",
                        resource=f"serviceAccount:{email} / key:{key.get('name', '').split('/')[-1]}",
                        finding=(
                            f"Service account key has not been rotated in {age_days} days "
                            f"(threshold: {_STALE_KEY_DAYS} days). Stale keys increase the blast radius of credential compromise."
                        ),
                        severity="HIGH",
                        recommendation=(
                            "Rotate service account keys at least every 90 days. "
                            "Prefer Workload Identity Federation to eliminate the need for long-lived keys."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _check_005_no_workload_identity(accounts: list[dict]) -> list[dict]:
    """GCP-005: Service accounts without Workload Identity Federation binding."""
    findings: list[dict] = []
    for account in accounts:
        email = account.get("email", "unknown")
        wif_binding = account.get("workloadIdentityBinding")
        if not wif_binding and account.get("keys"):
            # Only flag if they also have keys (otherwise no auth at all — different issue)
            findings.append(
                _finding(
                    check_id="GCP-005",
                    resource=f"serviceAccount:{email}",
                    finding=(
                        "Service account uses key-based authentication and has no Workload Identity "
                        "Federation binding configured. Key-based auth requires managing long-lived secrets."
                    ),
                    severity="MEDIUM",
                    recommendation=(
                        "Configure Workload Identity Federation and remove exported keys. "
                        "WIF allows workloads to impersonate service accounts without downloading key files."
                    ),
                    nist_csf_function="PROTECT",
                )
            )
    return findings


def _check_006_test_temp_sa(accounts: list[dict]) -> list[dict]:
    """GCP-006: Test/temporary service accounts found in production dataset."""
    findings: list[dict] = []
    for account in accounts:
        email = account.get("email", "unknown")
        display_name = account.get("displayName", "")
        description = account.get("description", "")
        searchable = f"{email} {display_name} {description}"
        if _TEST_TEMP_PATTERNS.search(searchable):
            findings.append(
                _finding(
                    check_id="GCP-006",
                    resource=f"serviceAccount:{email}",
                    finding=(
                        f"Service account '{email}' (display: '{display_name}') has test/temporary naming "
                        "conventions suggesting it was created for development or testing and should not "
                        "exist in a production environment."
                    ),
                    severity="MEDIUM",
                    recommendation=(
                        "Audit test and temporary service accounts. Delete or disable those not required "
                        "in production. Enforce a naming policy to prevent test accounts entering prod."
                    ),
                    nist_csf_function="IDENTIFY",
                )
            )
    return findings


def _check_007_editor_role(bindings: list[dict]) -> list[dict]:
    """GCP-007: roles/editor assigned at project scope."""
    findings: list[dict] = []
    for binding in bindings:
        role = binding.get("role", "")
        if role != "roles/editor":
            continue
        members = binding.get("members", [])
        for member in members:
            findings.append(
                _finding(
                    check_id="GCP-007",
                    resource=f"{role} → {member}",
                    finding=(
                        f"'{member}' holds the Editor role at project scope. "
                        "Editor grants read/write access to most GCP services and violates least-privilege."
                    ),
                    severity="HIGH",
                    recommendation=(
                        "Replace roles/editor with purpose-specific roles (e.g., roles/storage.objectAdmin, "
                        "roles/cloudsql.editor). Apply roles at the minimum required resource scope."
                    ),
                    nist_csf_function="PROTECT",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run() -> list[dict]:
    """Execute all 7 GCP IAM checks and return a flat list of findings."""
    policy = _load_json(_IAM_POLICY_PATH)
    sa_data = _load_json(_SERVICE_ACCOUNTS_PATH)

    bindings: list[dict] = policy.get("bindings", [])
    accounts: list[dict] = sa_data.get("accounts", [])

    findings: list[dict] = []
    findings.extend(_check_001_public_iam_bindings(bindings))
    findings.extend(_check_002_human_owner(bindings))
    findings.extend(_check_003_exported_sa_keys(accounts))
    findings.extend(_check_004_stale_sa_keys(accounts))
    findings.extend(_check_005_no_workload_identity(accounts))
    findings.extend(_check_006_test_temp_sa(accounts))
    findings.extend(_check_007_editor_role(bindings))

    return findings


if __name__ == "__main__":
    for f in run():
        print(f)
