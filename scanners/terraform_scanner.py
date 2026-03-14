"""
Terraform / IaC Security Scanner

Controls evaluated:
1. Public IAM bindings (allUsers / allAuthenticatedUsers)
2. Exported service account keys
3. Firewall rules allowing all ingress from 0.0.0.0/0
4. Storage buckets without uniform bucket-level access
5. OS Login disabled on compute instances
6. Full cloud-platform scope on compute instances
7. Missing bucket versioning
8. Broad projectIAM roles (owner / editor)
"""

from __future__ import annotations

import re
from pathlib import Path

import hcl2  # type: ignore[import]

_EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
_TF_PATH = _EXAMPLES_DIR / "main.tf"

_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
_BROAD_ROLES = {"roles/owner", "roles/editor"}


def _finding(check_id, resource, finding, severity, recommendation, nist_csf_function):
    return {
        "scanner": "terraform",
        "check_id": check_id,
        "resource": resource,
        "finding": finding,
        "severity": severity,
        "recommendation": recommendation,
        "nist_csf_function": nist_csf_function,
    }


def _load_tf(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return hcl2.load(fh)


def _iter_resources(tf: dict, resource_type: str):
    """Yield (resource_name, config_dict) for a given resource type."""
    for block in tf.get("resource", []):
        if not isinstance(block, dict):
            continue
        for rtype, instances in block.items():
            if rtype != resource_type:
                continue
            if isinstance(instances, dict):
                for rname, rconfig in instances.items():
                    cfg = rconfig[0] if isinstance(rconfig, list) else rconfig
                    yield rname, cfg


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def _check_tf_001_public_iam(tf: dict) -> list[dict]:
    """TF-001: allUsers / allAuthenticatedUsers in any IAM binding."""
    findings = []
    for rtype in ("google_project_iam_binding", "google_project_iam_member",
                  "google_storage_bucket_iam_binding", "google_storage_bucket_iam_member"):
        for rname, cfg in _iter_resources(tf, rtype):
            role = cfg.get("role", "")
            members_raw = cfg.get("members", cfg.get("member", []))
            members = [members_raw] if isinstance(members_raw, str) else (members_raw or [])
            for member in members:
                if member in _PUBLIC_MEMBERS:
                    sev = "CRITICAL" if "owner" in str(role).lower() else "HIGH"
                    findings.append(_finding(
                        "TF-001",
                        f"{rtype}.{rname}",
                        f"IAM binding grants '{role}' to public member '{member}'. "
                        "This exposes your project to the entire internet or all Google accounts.",
                        sev,
                        "Remove 'allUsers' and 'allAuthenticatedUsers' from all IAM bindings. "
                        "Replace with specific principals (user:, serviceAccount:, group:).",
                        "PROTECT",
                    ))
    return findings


def _check_tf_002_exported_sa_key(tf: dict) -> list[dict]:
    """TF-002: google_service_account_key resources (creates downloadable key files)."""
    findings = []
    for rname, _ in _iter_resources(tf, "google_service_account_key"):
        findings.append(_finding(
            "TF-002",
            f"google_service_account_key.{rname}",
            "Terraform creates an exported service account key. Key material leaves GCP's "
            "security perimeter and is stored in Terraform state (often plaintext).",
            "HIGH",
            "Delete the google_service_account_key resource and migrate to Workload Identity "
            "Federation. If keys are unavoidable, store in Secret Manager with rotation.",
            "PROTECT",
        ))
    return findings


def _check_tf_003_open_firewall(tf: dict) -> list[dict]:
    """TF-003: Firewall rules allowing all TCP ports from 0.0.0.0/0."""
    findings = []
    for rname, cfg in _iter_resources(tf, "google_compute_firewall"):
        source_ranges = cfg.get("source_ranges", []) or []
        if isinstance(source_ranges, str):
            source_ranges = [source_ranges]
        is_open_source = "0.0.0.0/0" in source_ranges or "::/0" in source_ranges

        for allow_block in cfg.get("allow", []) or []:
            ports_raw = allow_block.get("ports", []) or []
            if isinstance(ports_raw, str):
                ports_raw = [ports_raw]
            is_all_ports = not ports_raw or any(
                p in ("0-65535", "1-65535") for p in ports_raw
            )
            if is_open_source and is_all_ports:
                findings.append(_finding(
                    "TF-003",
                    f"google_compute_firewall.{rname}",
                    f"Firewall rule '{rname}' allows all TCP ports from 0.0.0.0/0 (the entire internet). "
                    "This creates a very large attack surface.",
                    "CRITICAL",
                    "Restrict source_ranges to known IP ranges and limit allowed ports to only "
                    "those required. Use firewall tags and VPC Service Controls to reduce scope.",
                    "PROTECT",
                ))
    return findings


def _check_tf_004_bucket_uniform_access(tf: dict) -> list[dict]:
    """TF-004: GCS bucket without uniform_bucket_level_access."""
    findings = []
    for rname, cfg in _iter_resources(tf, "google_storage_bucket"):
        ubla = cfg.get("uniform_bucket_level_access")
        if ubla is False or ubla == "false":
            findings.append(_finding(
                "TF-004",
                f"google_storage_bucket.{rname}",
                f"Bucket '{rname}' has uniform_bucket_level_access disabled. "
                "Object-level ACLs can bypass bucket IAM policies, leading to over-permissive access.",
                "HIGH",
                "Set 'uniform_bucket_level_access = true'. "
                "Migrate any object ACLs to bucket-level IAM policies beforehand.",
                "PROTECT",
            ))
    return findings


def _check_tf_005_os_login_disabled(tf: dict) -> list[dict]:
    """TF-005: OS Login disabled on compute instances."""
    findings = []
    for rname, cfg in _iter_resources(tf, "google_compute_instance"):
        metadata = cfg.get("metadata", {}) or {}
        os_login = str(metadata.get("enable-oslogin", "")).lower()
        if os_login == "false":
            findings.append(_finding(
                "TF-005",
                f"google_compute_instance.{rname}",
                f"Instance '{rname}' has OS Login disabled (enable-oslogin = false). "
                "Without OS Login, SSH access falls back to project/instance SSH keys "
                "which are harder to audit and revoke.",
                "MEDIUM",
                "Set 'enable-oslogin = \"true\"' in the instance metadata block. "
                "OS Login integrates with Cloud IAM for centralized SSH key management.",
                "PROTECT",
            ))
    return findings


def _check_tf_006_cloud_platform_scope(tf: dict) -> list[dict]:
    """TF-006: Compute instances using full cloud-platform scope."""
    findings = []
    for rname, cfg in _iter_resources(tf, "google_compute_instance"):
        for sa_block in cfg.get("service_account", []) or []:
            scopes = sa_block.get("scopes", []) or []
            if isinstance(scopes, str):
                scopes = [scopes]
            if "cloud-platform" in scopes or "https://www.googleapis.com/auth/cloud-platform" in scopes:
                findings.append(_finding(
                    "TF-006",
                    f"google_compute_instance.{rname}",
                    f"Instance '{rname}' uses the 'cloud-platform' scope, which grants the "
                    "instance's service account access to all Google Cloud APIs.",
                    "HIGH",
                    "Replace 'cloud-platform' with specific API scopes "
                    "(e.g., 'storage.read_only', 'logging.write'). "
                    "Apply least privilege at both the scope and IAM role level.",
                    "PROTECT",
                ))
    return findings


def _check_tf_007_bucket_versioning(tf: dict) -> list[dict]:
    """TF-007: GCS bucket without versioning enabled."""
    findings = []
    for rname, cfg in _iter_resources(tf, "google_storage_bucket"):
        versioning = cfg.get("versioning")
        versioning_enabled = False
        if isinstance(versioning, list) and versioning:
            versioning_enabled = bool(versioning[0].get("enabled"))
        elif isinstance(versioning, dict):
            versioning_enabled = bool(versioning.get("enabled"))
        if not versioning_enabled:
            findings.append(_finding(
                "TF-007",
                f"google_storage_bucket.{rname}",
                f"Bucket '{rname}' does not have versioning enabled. "
                "Accidental or malicious deletions/overwrites cannot be recovered.",
                "MEDIUM",
                "Add 'versioning { enabled = true }' to the bucket. "
                "Combine with Object Lifecycle rules to manage storage costs.",
                "RECOVER",
            ))
    return findings


def _check_tf_008_broad_project_iam(tf: dict) -> list[dict]:
    """TF-008: Owner or Editor role granted at project scope."""
    findings = []
    for rtype in ("google_project_iam_binding", "google_project_iam_member"):
        for rname, cfg in _iter_resources(tf, rtype):
            role = cfg.get("role", "")
            if role in _BROAD_ROLES:
                members_raw = cfg.get("members", cfg.get("member", []))
                members = [members_raw] if isinstance(members_raw, str) else (members_raw or [])
                for member in members:
                    sev = "CRITICAL" if role == "roles/owner" else "HIGH"
                    findings.append(_finding(
                        "TF-008",
                        f"{rtype}.{rname} → {member}",
                        f"Principal '{member}' is granted '{role}' at project scope. "
                        f"{'Owner' if role == 'roles/owner' else 'Editor'} grants unrestricted "
                        "access to GCP resources.",
                        sev,
                        f"Replace '{role}' with purpose-specific predefined or custom roles. "
                        "Apply at the minimum necessary resource scope (not project-wide).",
                        "PROTECT",
                    ))
    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run() -> list[dict]:
    """Execute all 8 Terraform checks and return a flat list of findings."""
    tf = _load_tf(_TF_PATH)

    findings: list[dict] = []
    findings.extend(_check_tf_001_public_iam(tf))
    findings.extend(_check_tf_002_exported_sa_key(tf))
    findings.extend(_check_tf_003_open_firewall(tf))
    findings.extend(_check_tf_004_bucket_uniform_access(tf))
    findings.extend(_check_tf_005_os_login_disabled(tf))
    findings.extend(_check_tf_006_cloud_platform_scope(tf))
    findings.extend(_check_tf_007_bucket_versioning(tf))
    findings.extend(_check_tf_008_broad_project_iam(tf))

    return findings


if __name__ == "__main__":
    for f in run():
        print(f)
