"""
NIST CSF and Zero Trust Scoring Engine
Phase 3 — CloudGuard Security Reviewer

Consumes a flat list of finding dicts (from all 4 scanners) and produces:

  - NIST CSF 5-function scores (IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER)
  - Zero Trust pillar scores (Identity, Workload, Network, Data, DevOps)
  - Overall score (average of ZT pillars)
  - Maturity band string derived from the overall ZT score
  - Severity breakdown counts
  - Full findings list

Deduction rules (per finding, per domain):
    CRITICAL : -20
    HIGH     : -10
    MEDIUM   :  -5
    LOW      :  -2

Each dimension starts at 100 and is floored at 0.
"""

from __future__ import annotations

import json
import os
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NIST_FUNCTIONS: tuple[str, ...] = (
    "IDENTIFY",
    "PROTECT",
    "DETECT",
    "RESPOND",
    "RECOVER",
)

_SEVERITY_DEDUCTION: dict[str, int] = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}

# Zero Trust pillar → set of check_id prefixes or full IDs that belong to it.
# A finding is mapped to a ZT pillar if its check_id starts with one of the
# listed prefixes, OR matches one of the explicit IDs listed.
_ZT_PILLAR_CHECK_IDS: dict[str, set[str]] = {
    "Identity": {"GCP-001", "GCP-002", "GCP-005", "TF-001"},
    "Workload": {
        "CONTAINER-001",
        "CONTAINER-002",
        "CONTAINER-003",
        "CONTAINER-004",
        "CONTAINER-005",
        "CONTAINER-006",
        "CONTAINER-007",
        "CONTAINER-008",
        "CONTAINER-009",
        "CONTAINER-010",
        "GCP-003",
        "GCP-004",
    },
    "Network": {"GCP-001", "CONTAINER-002"},
    "Data": {"TF-003", "TF-004", "CONTAINER-003"},
    "DevOps": {
        "CICD-001",
        "CICD-002",
        "CICD-003",
        "CICD-004",
        "CICD-005",
        "CICD-006",
        "TF-002",
    },
}

_ZT_PILLARS: tuple[str, ...] = ("Identity", "Workload", "Network", "Data", "DevOps")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _deduction(severity: str) -> int:
    """Return the point deduction for a given severity string."""
    return _SEVERITY_DEDUCTION.get(severity.upper(), 0)


def _compute_scores(
    findings: list[dict[str, Any]],
    dimension_map: dict[str, set[str]],
    key_field: str,
    all_dimensions: tuple[str, ...],
) -> dict[str, int]:
    """
    Generic scorer.

    Parameters
    ----------
    findings       : flat list of finding dicts
    dimension_map  : {dimension_name: {check_id, ...}} — membership mapping
    key_field      : field in each finding that selects the dimension
                     (used for NIST CSF: 'nist_csf_function')
                     Pass an empty string to skip field-based mapping and
                     rely solely on dimension_map check_id matching.
    all_dimensions : ordered tuple of all dimension names

    Returns
    -------
    dict[dimension_name, score_0_100]
    """
    deductions: dict[str, int] = {d: 0 for d in all_dimensions}

    for finding in findings:
        sev = finding.get("severity", "LOW").upper()
        pts = _deduction(sev)
        check_id = finding.get("check_id", "")

        if key_field:
            # NIST path: use the field value as the dimension key
            dim = finding.get(key_field, "PROTECT").upper()
            if dim in deductions:
                deductions[dim] += pts
        else:
            # ZT path: a finding may belong to multiple pillars
            for pillar, ids in dimension_map.items():
                if check_id in ids:
                    deductions[pillar] += pts

    return {d: max(0, 100 - deductions[d]) for d in all_dimensions}


def _maturity_band(avg_score: float) -> str:
    """Return the maturity band label for a given average ZT score."""
    if avg_score < 40:
        return "Initial"
    if avg_score < 60:
        return "Developing"
    if avg_score < 80:
        return "Defined"
    return "Optimising"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compute NIST CSF and Zero Trust scores from a flat list of findings.

    Parameters
    ----------
    findings : list of finding dicts.  Each dict must contain at minimum:
        - 'check_id'          (str) e.g. "GCP-001"
        - 'severity'          (str) one of CRITICAL / HIGH / MEDIUM / LOW
        - 'nist_csf_function' (str) one of IDENTIFY / PROTECT / DETECT /
                                        RESPOND / RECOVER

    Returns
    -------
    dict with the structure documented in the module docstring.
    """
    # --- NIST CSF scores ---
    nist_scores = _compute_scores(
        findings=findings,
        dimension_map={},          # unused for NIST path
        key_field="nist_csf_function",
        all_dimensions=_NIST_FUNCTIONS,
    )

    # --- Zero Trust scores ---
    zt_scores = _compute_scores(
        findings=findings,
        dimension_map=_ZT_PILLAR_CHECK_IDS,
        key_field="",              # ZT uses check_id membership, not a field
        all_dimensions=_ZT_PILLARS,
    )

    # --- Overall / maturity ---
    overall_score = int(sum(zt_scores.values()) / len(_ZT_PILLARS))
    maturity = _maturity_band(overall_score)

    # --- Severity breakdown ---
    by_severity: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    for finding in findings:
        sev = finding.get("severity", "LOW").upper()
        if sev in by_severity:
            by_severity[sev] += 1

    return {
        "nist_scores": {k: nist_scores[k] for k in _NIST_FUNCTIONS},
        "zt_scores": {k: zt_scores[k] for k in _ZT_PILLARS},
        "overall_score": overall_score,
        "maturity_band": maturity,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from scanners.gcp_iam_scanner import run as gcp
    from scanners.container_scanner import run as containers
    from scanners.cicd_scanner import run as cicd
    from scanners.terraform_scanner import run as tf

    os.makedirs("output", exist_ok=True)

    all_findings = gcp() + containers() + cicd() + tf()
    result = score(all_findings)

    output_path = os.path.join("output", "scores.json")
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(json.dumps(result, indent=2))
    print(f"\n✅  Scores written to {output_path}")
