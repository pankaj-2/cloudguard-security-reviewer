"""
Container Security Scanner (Docker + Kubernetes)

Controls evaluated:
1. Privileged containers
2. Host network mode
3. Hardcoded secrets in environment variables
4. Dangerous volume mounts (host path mounts)
5. Missing security context
6. Running as root (no user specified)
7. Unpinned :latest image tags
8. Missing resource limits (K8s)
9. Overly broad RBAC (ClusterRole admin)
10. automountServiceAccountToken: true with broad RBAC
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
_COMPOSE_PATH = _EXAMPLES_DIR / "docker-compose.yml"
_K8S_PATH = _EXAMPLES_DIR / "k8s_deployment.yaml"

# ---------------------------------------------------------------------------
# Patterns for secret detection in env var values
# ---------------------------------------------------------------------------
_SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|jwt)",
    re.IGNORECASE,
)
_PLACEHOLDER_PATTERN = re.compile(
    r"^\$\{[^}]+\}$|^\$[A-Z_][A-Z0-9_]*$|^<[^>]+>$",
    re.IGNORECASE,
)

_LATEST_TAG_PATTERN = re.compile(r":latest$", re.IGNORECASE)
_NO_TAG_PATTERN = re.compile(r"^[^:@]+$")  # no tag or digest at all


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
        "scanner": "container",
        "check_id": check_id,
        "resource": resource,
        "finding": finding,
        "severity": severity,
        "recommendation": recommendation,
        "nist_csf_function": nist_csf_function,
    }


def _load_all_yaml_docs(path: Path) -> list[Any]:
    """Load a YAML file that may contain multiple documents separated by ---."""
    with path.open(encoding="utf-8") as fh:
        return list(yaml.safe_load_all(fh))


def _is_hardcoded_secret(key: str, value: Any) -> bool:
    """Return True when the key looks secret-like AND the value is not an env-var reference."""
    if not isinstance(value, str):
        return False
    if not value.strip():
        return False
    if _PLACEHOLDER_PATTERN.match(value.strip()):
        return False
    return bool(_SECRET_KEY_PATTERN.search(key))


def _image_is_latest(image: str | None) -> bool:
    if not image:
        return False
    return bool(_LATEST_TAG_PATTERN.search(image)) or bool(_NO_TAG_PATTERN.match(image))


# ---------------------------------------------------------------------------
# Docker-Compose checks
# ---------------------------------------------------------------------------

def _compose_check_001_privileged(services: dict) -> list[dict]:
    """CONTAINER-001: Privileged containers."""
    findings = []
    for svc_name, svc in services.items():
        if svc and svc.get("privileged") is True:
            findings.append(
                _finding(
                    check_id="CONTAINER-001",
                    resource=f"docker-compose/service:{svc_name}",
                    finding=f"Service '{svc_name}' runs as a privileged container "
                            "(privileged: true). Privileged mode grants full host access.",
                    severity="CRITICAL",
                    recommendation=(
                        "Remove 'privileged: true'. "
                        "Use specific Linux capabilities (cap_add) for only what is needed. "
                        "Prefer rootless containers and AppArmor/seccomp profiles."
                    ),
                    nist_csf_function="PROTECT",
                )
            )
    return findings


def _compose_check_002_host_network(services: dict) -> list[dict]:
    """CONTAINER-002: Host network mode."""
    findings = []
    for svc_name, svc in services.items():
        if svc and svc.get("network_mode") == "host":
            findings.append(
                _finding(
                    check_id="CONTAINER-002",
                    resource=f"docker-compose/service:{svc_name}",
                    finding=f"Service '{svc_name}' uses host network mode. "
                            "This bypasses container network isolation.",
                    severity="CRITICAL",
                    recommendation=(
                        "Remove 'network_mode: host'. "
                        "Use bridge networking with explicit port mappings instead."
                    ),
                    nist_csf_function="PROTECT",
                )
            )
    return findings


def _compose_check_003_hardcoded_secrets(services: dict) -> list[dict]:
    """CONTAINER-003: Hardcoded secrets in environment variables."""
    findings = []
    for svc_name, svc in services.items():
        if not svc:
            continue
        env = svc.get("environment", {})
        # docker-compose supports both dict and list formats
        if isinstance(env, list):
            env_dict: dict = {}
            for item in env:
                if "=" in str(item):
                    k, _, v = str(item).partition("=")
                    env_dict[k] = v
                else:
                    env_dict[str(item)] = ""
            env = env_dict
        if isinstance(env, dict):
            for key, value in env.items():
                if _is_hardcoded_secret(key, value):
                    findings.append(
                        _finding(
                            check_id="CONTAINER-003",
                            resource=f"docker-compose/service:{svc_name}/env:{key}",
                            finding=f"Service '{svc_name}' has a potential hardcoded secret in "
                                    f"environment variable '{key}'.",
                            severity="HIGH",
                            recommendation=(
                                "Remove hardcoded credentials from docker-compose files. "
                                "Use Docker Secrets, environment variable files (.env), "
                                "or a secret manager (e.g., Vault, AWS Secrets Manager)."
                            ),
                            nist_csf_function="PROTECT",
                        )
                    )
    return findings


def _compose_check_004_host_volume_mounts(services: dict) -> list[dict]:
    """CONTAINER-004: Dangerous host path volume mounts."""
    findings = []
    _sensitive_paths = {"/etc", "/proc", "/sys", "/var/run", "/root", "/home"}
    for svc_name, svc in services.items():
        if not svc:
            continue
        for vol in svc.get("volumes", []):
            vol_str = str(vol)
            # Detect host:container bind mounts (start with /)
            if vol_str.startswith("/") or (isinstance(vol, str) and ":" in vol and vol.split(":")[0].startswith("/")):
                host_path = vol_str.split(":")[0] if ":" in vol_str else vol_str
                is_sensitive = any(host_path.startswith(p) for p in _sensitive_paths)
                severity = "CRITICAL" if is_sensitive else "MEDIUM"
                findings.append(
                    _finding(
                        check_id="CONTAINER-004",
                        resource=f"docker-compose/service:{svc_name}/volume:{vol_str}",
                        finding=f"Service '{svc_name}' mounts host path '{host_path}' into the container. "
                                + ("This path is sensitive and may expose system files." if is_sensitive else
                                   "Host path mounts can expose host data to the container."),
                        severity=severity,
                        recommendation=(
                            "Replace host path mounts with named Docker volumes. "
                            "For system-level access, evaluate whether it is strictly necessary "
                            "and apply read-only mounts where possible."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _compose_check_006_root_containers(services: dict) -> list[dict]:
    """CONTAINER-006: Containers running as root (no 'user' directive)."""
    findings = []
    for svc_name, svc in services.items():
        if not svc:
            continue
        if "user" not in svc:
            findings.append(
                _finding(
                    check_id="CONTAINER-006",
                    resource=f"docker-compose/service:{svc_name}",
                    finding=f"Service '{svc_name}' has no 'user' directive. "
                            "Containers run as root (UID 0) by default.",
                    severity="HIGH",
                    recommendation=(
                        "Add 'user: \"<uid>:<gid>\"' to the service definition. "
                        "Use a non-root UID (e.g., 1000:1000). "
                        "Ensure the base image supports running as non-root."
                    ),
                    nist_csf_function="PROTECT",
                )
            )
    return findings


def _compose_check_007_latest_tags(services: dict) -> list[dict]:
    """CONTAINER-007: Unpinned :latest image tags."""
    findings = []
    for svc_name, svc in services.items():
        if not svc:
            continue
        image = svc.get("image", "")
        if _image_is_latest(image):
            findings.append(
                _finding(
                    check_id="CONTAINER-007",
                    resource=f"docker-compose/service:{svc_name}/image:{image}",
                    finding=f"Service '{svc_name}' uses unpinned image tag '{image}'. "
                            ":latest is mutable and may pull a different image silently.",
                    severity="MEDIUM",
                    recommendation=(
                        "Pin images to an immutable digest: "
                        "'image: myimage:v1.2.3@sha256:<digest>'. "
                        "Use image scanning in CI/CD to validate pinned images."
                    ),
                    nist_csf_function="PROTECT",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Kubernetes checks
# ---------------------------------------------------------------------------

def _k8s_check_001_privileged(docs: list[Any]) -> list[dict]:
    """CONTAINER-001 (K8s): Privileged containers in Pod specs."""
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")
        if kind not in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
            continue
        containers = _get_containers(doc)
        for ctr in containers:
            sc = ctr.get("securityContext", {}) or {}
            if sc.get("privileged") is True:
                findings.append(
                    _finding(
                        check_id="CONTAINER-001",
                        resource=f"k8s/{kind}:{name}/container:{ctr.get('name','?')}",
                        finding=f"Container '{ctr.get('name')}' in {kind} '{name}' is privileged. "
                                "Privileged K8s containers can escape to the host.",
                        severity="CRITICAL",
                        recommendation=(
                            "Set 'securityContext.privileged: false'. "
                            "Use specific capabilities (capabilities.add) for only what is required."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _k8s_check_002_host_network(docs: list[Any]) -> list[dict]:
    """CONTAINER-002 (K8s): hostNetwork: true in Pod specs."""
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")
        pod_spec = _get_pod_spec(doc)
        if pod_spec and pod_spec.get("hostNetwork") is True:
            findings.append(
                _finding(
                    check_id="CONTAINER-002",
                    resource=f"k8s/{kind}:{name}",
                    finding=f"{kind} '{name}' has hostNetwork: true. "
                            "Pods share the host network namespace, bypassing network isolation.",
                    severity="CRITICAL",
                    recommendation=(
                        "Set 'hostNetwork: false' or remove the field. "
                        "Use ClusterIP services and ingress controllers instead of direct host networking."
                    ),
                    nist_csf_function="PROTECT",
                )
            )
    return findings


def _k8s_check_003_hardcoded_secrets(docs: list[Any]) -> list[dict]:
    """CONTAINER-003 (K8s): Hardcoded secrets in env values."""
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")
        if kind not in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
            continue
        for ctr in _get_containers(doc):
            for env_entry in ctr.get("env", []) or []:
                key = env_entry.get("name", "")
                value = env_entry.get("value")
                if value is not None and _is_hardcoded_secret(key, str(value)):
                    findings.append(
                        _finding(
                            check_id="CONTAINER-003",
                            resource=f"k8s/{kind}:{name}/container:{ctr.get('name','?')}/env:{key}",
                            finding=f"Container '{ctr.get('name')}' has a potential hardcoded secret "
                                    f"in env var '{key}'.",
                            severity="HIGH",
                            recommendation=(
                                "Use Kubernetes Secrets with secretKeyRef or a secrets manager "
                                "(e.g., Vault, AWS Secrets Manager with CSI driver). "
                                "Never store credentials as plaintext in manifests."
                            ),
                            nist_csf_function="PROTECT",
                        )
                    )
    return findings


def _k8s_check_004_host_path_volumes(docs: list[Any]) -> list[dict]:
    """CONTAINER-004 (K8s): hostPath volume mounts."""
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")
        pod_spec = _get_pod_spec(doc)
        if not pod_spec:
            continue
        for vol in pod_spec.get("volumes", []) or []:
            hp = vol.get("hostPath", {})
            if hp:
                host_path = hp.get("path", "")
                findings.append(
                    _finding(
                        check_id="CONTAINER-004",
                        resource=f"k8s/{kind}:{name}/volume:{vol.get('name','?')}",
                        finding=f"{kind} '{name}' mounts host path '{host_path}' via hostPath volume. "
                                "This grants container access to host filesystem data.",
                        severity="MEDIUM",
                        recommendation=(
                            "Replace hostPath volumes with PersistentVolumeClaims backed by a "
                            "storage class. For log access use sidecar log-forwarder patterns."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _k8s_check_005_missing_security_context(docs: list[Any]) -> list[dict]:
    """CONTAINER-005 (K8s): Containers with no securityContext defined."""
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")
        if kind not in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
            continue
        for ctr in _get_containers(doc):
            if not ctr.get("securityContext"):
                findings.append(
                    _finding(
                        check_id="CONTAINER-005",
                        resource=f"k8s/{kind}:{name}/container:{ctr.get('name','?')}",
                        finding=f"Container '{ctr.get('name')}' in {kind} '{name}' has no "
                                "securityContext. Container will inherit permissive defaults.",
                        severity="HIGH",
                        recommendation=(
                            "Define a securityContext with at minimum: "
                            "allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, "
                            "runAsNonRoot: true, and capabilities.drop: [ALL]."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _k8s_check_006_run_as_root(docs: list[Any]) -> list[dict]:
    """CONTAINER-006 (K8s): Containers explicitly set to run as root (runAsUser: 0)."""
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")
        if kind not in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
            continue
        for ctr in _get_containers(doc):
            sc = ctr.get("securityContext") or {}
            if sc.get("runAsUser") == 0:
                findings.append(
                    _finding(
                        check_id="CONTAINER-006",
                        resource=f"k8s/{kind}:{name}/container:{ctr.get('name','?')}",
                        finding=f"Container '{ctr.get('name')}' in {kind} '{name}' explicitly "
                                "sets runAsUser: 0 (root). Root containers can escalate to host.",
                        severity="HIGH",
                        recommendation=(
                            "Set runAsUser to a non-zero UID (e.g., 1000). "
                            "Add runAsNonRoot: true to the pod securityContext as an additional guard."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _k8s_check_007_latest_tags(docs: list[Any]) -> list[dict]:
    """CONTAINER-007 (K8s): Unpinned :latest image tags."""
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")
        if kind not in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
            continue
        for ctr in _get_containers(doc):
            image = ctr.get("image", "")
            if _image_is_latest(image):
                findings.append(
                    _finding(
                        check_id="CONTAINER-007",
                        resource=f"k8s/{kind}:{name}/container:{ctr.get('name','?')}/image:{image}",
                        finding=f"Container '{ctr.get('name')}' uses unpinned image '{image}'. "
                                "Mutable tags can lead to unintended image upgrades.",
                        severity="MEDIUM",
                        recommendation=(
                            "Pin images to a SHA256 digest: "
                            "'image: myimage:v1.2.3@sha256:<hash>'. "
                            "Enforce digest pinning via admission controller or OPA policy."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _k8s_check_008_missing_resource_limits(docs: list[Any]) -> list[dict]:
    """CONTAINER-008: Containers missing CPU/memory resource limits."""
    findings = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")
        if kind not in ("Deployment", "DaemonSet", "StatefulSet", "Pod"):
            continue
        for ctr in _get_containers(doc):
            resources = ctr.get("resources") or {}
            limits = resources.get("limits") or {}
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(
                    _finding(
                        check_id="CONTAINER-008",
                        resource=f"k8s/{kind}:{name}/container:{ctr.get('name','?')}",
                        finding=f"Container '{ctr.get('name')}' in {kind} '{name}' is missing "
                                "CPU and/or memory resource limits. Unbounded containers risk "
                                "resource exhaustion (DoS).",
                        severity="MEDIUM",
                        recommendation=(
                            "Define both 'resources.limits.cpu' and 'resources.limits.memory'. "
                            "Also set 'resources.requests' to aid scheduler placement. "
                            "Consider LimitRange objects to enforce defaults cluster-wide."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _k8s_check_009_broad_rbac(docs: list[Any]) -> list[dict]:
    """CONTAINER-009: ClusterRoleBinding granting cluster-admin or broad admin roles."""
    findings = []
    _broad_roles = {"cluster-admin", "admin", "edit"}
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") != "ClusterRoleBinding":
            continue
        name = doc.get("metadata", {}).get("name", "unknown")
        role_ref = doc.get("roleRef", {}) or {}
        role_name = role_ref.get("name", "") or role_ref.get("apiRef", "")
        if role_name in _broad_roles:
            subjects = doc.get("subjects", []) or []
            for subj in subjects:
                findings.append(
                    _finding(
                        check_id="CONTAINER-009",
                        resource=f"k8s/ClusterRoleBinding:{name}/subject:{subj.get('name','?')}",
                        finding=f"ClusterRoleBinding '{name}' grants '{role_name}' to "
                                f"'{subj.get('kind','?')}:{subj.get('name','?')}'. "
                                "This provides cluster-wide privileged access.",
                        severity="HIGH",
                        recommendation=(
                            "Replace cluster-admin with narrowly scoped Roles and RoleBindings "
                            "limited to specific namespaces and verbs. "
                            "Apply least-privilege RBAC using the principle of minimal required access."
                        ),
                        nist_csf_function="PROTECT",
                    )
                )
    return findings


def _k8s_check_010_automount_sa_token(docs: list[Any]) -> list[dict]:
    """CONTAINER-010: automountServiceAccountToken: true combined with broad RBAC."""
    findings = []
    # Collect service accounts with automount enabled
    automount_sa: set[str] = set()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") == "ServiceAccount":
            if doc.get("automountServiceAccountToken") is True:
                sa_name = doc.get("metadata", {}).get("name", "")
                sa_ns = doc.get("metadata", {}).get("namespace", "default")
                automount_sa.add(f"{sa_ns}/{sa_name}")

    # Collect service accounts bound to broad cluster roles
    broad_sa: set[str] = set()
    _broad_roles = {"cluster-admin", "admin", "edit"}
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") in ("ClusterRoleBinding", "RoleBinding"):
            role_ref = doc.get("roleRef", {}) or {}
            role_name = role_ref.get("name", "") or role_ref.get("apiRef", "")
            if role_name in _broad_roles:
                for subj in doc.get("subjects", []) or []:
                    if subj.get("kind") == "ServiceAccount":
                        ns = subj.get("namespace", "default")
                        broad_sa.add(f"{ns}/{subj.get('name', '')}")

    risky_sa = automount_sa & broad_sa
    for sa_key in risky_sa:
        findings.append(
            _finding(
                check_id="CONTAINER-010",
                resource=f"k8s/ServiceAccount:{sa_key}",
                finding=f"ServiceAccount '{sa_key}' has automountServiceAccountToken: true "
                        "and is bound to a broad RBAC role. Any pod using this SA automatically "
                        "receives a high-privilege token.",
                severity="HIGH",
                recommendation=(
                    "Set 'automountServiceAccountToken: false' on the ServiceAccount "
                    "and opt-in per-pod only where required. "
                    "Restrict the bound role to minimal required permissions."
                ),
                nist_csf_function="PROTECT",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Pod spec navigation helpers
# ---------------------------------------------------------------------------

def _get_pod_spec(doc: dict) -> dict | None:
    kind = doc.get("kind", "")
    if kind == "Pod":
        return doc.get("spec") or {}
    if kind in ("Deployment", "DaemonSet", "StatefulSet"):
        return (doc.get("spec", {}) or {}).get("template", {}).get("spec") or {}
    return None


def _get_containers(doc: dict) -> list[dict]:
    pod_spec = _get_pod_spec(doc)
    if not pod_spec:
        return []
    containers = list(pod_spec.get("containers") or [])
    containers += list(pod_spec.get("initContainers") or [])
    return [c for c in containers if c]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run() -> list[dict]:
    """Execute all 10 container security checks and return a flat list of findings."""
    # Load inputs
    with _COMPOSE_PATH.open(encoding="utf-8") as fh:
        compose_data = yaml.safe_load(fh) or {}
    services: dict = compose_data.get("services", {}) or {}

    k8s_docs: list[Any] = _load_all_yaml_docs(_K8S_PATH)

    findings: list[dict] = []

    # Docker-Compose checks
    findings.extend(_compose_check_001_privileged(services))
    findings.extend(_compose_check_002_host_network(services))
    findings.extend(_compose_check_003_hardcoded_secrets(services))
    findings.extend(_compose_check_004_host_volume_mounts(services))
    # check_005 is K8s-specific (securityContext concept); Docker has no direct equivalent
    findings.extend(_compose_check_006_root_containers(services))
    findings.extend(_compose_check_007_latest_tags(services))

    # Kubernetes checks
    findings.extend(_k8s_check_001_privileged(k8s_docs))
    findings.extend(_k8s_check_002_host_network(k8s_docs))
    findings.extend(_k8s_check_003_hardcoded_secrets(k8s_docs))
    findings.extend(_k8s_check_004_host_path_volumes(k8s_docs))
    findings.extend(_k8s_check_005_missing_security_context(k8s_docs))
    findings.extend(_k8s_check_006_run_as_root(k8s_docs))
    findings.extend(_k8s_check_007_latest_tags(k8s_docs))
    findings.extend(_k8s_check_008_missing_resource_limits(k8s_docs))
    findings.extend(_k8s_check_009_broad_rbac(k8s_docs))
    findings.extend(_k8s_check_010_automount_sa_token(k8s_docs))

    return findings


if __name__ == "__main__":
    for f in run():
        print(f)
