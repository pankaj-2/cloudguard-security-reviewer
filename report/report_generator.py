"""
Report Generator

Produces a Markdown security report from:
  - All scanner findings (flat list of dicts)
  - NIST CSF scores (from nist_scorer.score())
  - An AI-generated executive summary (optional; str or None)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader

# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------
_TEMPLATE = """\
# CloudGuard Security Report

**Generated:** {{ generated_at }}
**Risk Tier:** {{ scores.risk_tier }}
**Overall Security Score:** {{ scores.overall_score }}/100
**Total Findings:** {{ scores.total_findings }}

---

## Executive Summary

{% if ai_summary %}
{{ ai_summary }}
{% else %}
*No AI summary available. Set GEMINI_API_KEY to enable Gemini-powered analysis.*
{% endif %}

---

## NIST CSF Score Breakdown

| Function   | Score |
|------------|-------|
{% for func, score in scores.function_scores.items() -%}
| {{ func.ljust(10) }} | {{ score }}/100 |
{% endfor %}

---

## Severity Breakdown

| Severity | Count |
|----------|-------|
{% for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] -%}
| {{ sev.ljust(8) }} | {{ scores.severity_counts.get(sev, 0) }} |
{% endfor %}

---

## Findings

{% for scanner_name, scanner_findings in grouped_findings.items() %}
### {{ scanner_name | upper }} Scanner ({{ scanner_findings | length }} finding(s))

{% for f in scanner_findings %}
#### [{{ f.check_id }}] {{ f.severity }} — {{ f.resource }}

**Finding:** {{ f.finding }}

**Recommendation:** {{ f.recommendation }}

**NIST CSF:** {{ f.nist_csf_function }}

---
{% endfor %}
{% endfor %}
"""


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def generate(
    findings: list[dict[str, Any]],
    scores: dict[str, Any],
    ai_summary: str | None = None,
    output_path: Path | None = None,
) -> str:
    """
    Render the Markdown report and optionally write it to disk.

    Parameters
    ----------
    findings     : flat list of finding dicts from all scanners
    scores       : dict returned by nist_scorer.score()
    ai_summary   : AI-generated executive summary text (or None)
    output_path  : if provided, the report is saved to this path

    Returns
    -------
    str : the rendered Markdown report
    """
    # Group findings by scanner
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        scanner = f.get("scanner", "unknown")
        grouped.setdefault(scanner, []).append(f)

    # Sort each group: CRITICAL first, then HIGH, MEDIUM, LOW
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for scanner_findings in grouped.values():
        scanner_findings.sort(key=lambda x: _sev_order.get(x.get("severity", "LOW"), 4))

    env = Environment(loader=BaseLoader(), keep_trailing_newline=True)
    template = env.from_string(_TEMPLATE)

    rendered = template.render(
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        scores=scores,
        grouped_findings=grouped,
        ai_summary=ai_summary,
    )

    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        print(f"[report] Report saved to: {output_path}")

    return rendered
