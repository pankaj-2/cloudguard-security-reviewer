"""
NIST CSF Scorer

Consumes a flat list of finding dicts (from any scanner) and produces:
  - A per-function score (0–100) for each NIST CSF function
  - An overall score (0–100)
  - A severity breakdown
  - A short risk-tier label (CRITICAL / HIGH / MEDIUM / LOW)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

# ---------------------------------------------------------------------------
# Severity → numerical weight (used to compute scores)
# ---------------------------------------------------------------------------
_SEVERITY_WEIGHT: dict[str, int] = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
}

# Maximum possible deduction per NIST function so that scores bottom out at 0.
_BASE_CAPACITY_PER_FUNCTION = 100

# NIST CSF 2.0 functions we track
_ALL_FUNCTIONS = ("IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER")


def score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Parameters
    ----------
    findings : list of finding dicts (each has at least 'severity' and 'nist_csf_function')

    Returns
    -------
    dict with keys:
        function_scores   : dict[function_name, 0-100]
        overall_score     : int (0-100)
        severity_counts   : dict[severity, int]
        risk_tier         : str  (CRITICAL / HIGH / MEDIUM / LOW / PASS)
        total_findings    : int
    """
    # Count findings per function
    function_deduction: dict[str, int] = defaultdict(int)
    severity_counts: dict[str, int] = defaultdict(int)

    for finding in findings:
        func = finding.get("nist_csf_function", "PROTECT").upper()
        sev = finding.get("severity", "MEDIUM").upper()
        weight = _SEVERITY_WEIGHT.get(sev, 2)
        function_deduction[func] += weight
        severity_counts[sev] += 1

    # Compute per-function scores
    function_scores: dict[str, int] = {}
    for func in _ALL_FUNCTIONS:
        deduction = function_deduction.get(func, 0)
        # Normalise: every 20 weight-points = 20 points off, floored at 0
        raw_score = max(0, _BASE_CAPACITY_PER_FUNCTION - deduction)
        function_scores[func] = int(min(100, raw_score))

    overall_score = int(sum(function_scores.values()) / len(_ALL_FUNCTIONS))

    # Risk tier
    if severity_counts.get("CRITICAL", 0) > 0:
        risk_tier = "CRITICAL"
    elif severity_counts.get("HIGH", 0) > 0:
        risk_tier = "HIGH"
    elif severity_counts.get("MEDIUM", 0) > 0:
        risk_tier = "MEDIUM"
    elif findings:
        risk_tier = "LOW"
    else:
        risk_tier = "PASS"

    return {
        "function_scores": function_scores,
        "overall_score": overall_score,
        "severity_counts": dict(severity_counts),
        "risk_tier": risk_tier,
        "total_findings": len(findings),
    }
