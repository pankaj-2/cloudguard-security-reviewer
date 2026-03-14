"""
CloudGuard Report Generator — Phase 4
======================================
Generates output/cloudguard_report.html: a single self-contained HTML file
(all CSS inline, no JS frameworks, pure HTML <details>/<summary> for accordions).

Public entry-point
------------------
    generate_report(scores: dict) -> None

`scores` is the dict returned by scoring.nist_scorer.score().
It contains:
    - scores["overall_score"]   int 0-100
    - scores["maturity_band"]   str
    - scores["by_severity"]     dict  {"CRITICAL":n, "HIGH":n, ...}
    - scores["nist_scores"]     dict  {"IDENTIFY":n, ...}
    - scores["zt_scores"]       dict  {"Identity":n, ...}
    - scores["findings"]        list of finding dicts
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_OUTPUT_DIR = Path("output")
_OUTPUT_FILE = _OUTPUT_DIR / "cloudguard_report.html"

# ---------------------------------------------------------------------------
# GCP IAM check catalogue (7 checks from gcp_iam_scanner docstring)
# ---------------------------------------------------------------------------
_GCP_IAM_CHECKS = [
    ("GCP-001", "allUsers / allAuthenticatedUsers IAM bindings (roles/owner or any)"),
    ("GCP-002", "Human users assigned Owner role at project level"),
    ("GCP-003", "Exported user-managed service account keys"),
    ("GCP-004", "Service account keys not rotated in >90 days"),
    ("GCP-005", "Service accounts not using Workload Identity Federation"),
    ("GCP-006", "Test/temp service accounts in production"),
    ("GCP-007", "Editor role assigned at project scope"),
]

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SEV_BG = {
    "CRITICAL": "#fee2e2",
    "HIGH": "#fef3c7",
    "MEDIUM": "#eff6ff",
    "LOW": "#f0fdf4",
}
_SEV_BADGE = {
    "CRITICAL": "background:#dc2626;color:#fff",
    "HIGH": "background:#d97706;color:#fff",
    "MEDIUM": "background:#2563eb;color:#fff",
    "LOW": "background:#16a34a;color:#fff",
}

# ---------------------------------------------------------------------------
# Maturity badge colours
# ---------------------------------------------------------------------------
_MATURITY_COLOUR = {
    "Initial": "#dc2626",
    "Developing": "#d97706",
    "Defined": "#2563eb",
    "Optimising": "#16a34a",
}

# ---------------------------------------------------------------------------
# Effort heuristics (check_id prefix → effort)
# ---------------------------------------------------------------------------
_EFFORT_MAP = {
    "GCP-001": "High",
    "GCP-002": "Med",
    "GCP-003": "Med",
    "GCP-004": "Low",
    "GCP-005": "High",
    "GCP-006": "Low",
    "GCP-007": "Med",
    "CONTAINER": "Med",
    "CICD": "Low",
    "TF": "Med",
}


def _effort(check_id: str) -> str:
    if check_id in _EFFORT_MAP:
        return _EFFORT_MAP[check_id]
    prefix = check_id.split("-")[0]
    return _EFFORT_MAP.get(prefix, "Med")


# ---------------------------------------------------------------------------
# Bar colour helper
# ---------------------------------------------------------------------------
def _bar_colour(score: int) -> str:
    if score >= 70:
        return "#16a34a"
    if score >= 40:
        return "#d97706"
    return "#dc2626"


# ---------------------------------------------------------------------------
# Gemini executive summary
# ---------------------------------------------------------------------------

def _build_top_findings_text(findings: list[dict[str, Any]]) -> str:
    sorted_f: list[dict[str, Any]] = sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 4))
    top = sorted_f[:5]
    lines = []
    for i, f in enumerate(top, 1):
        lines.append(
            f"{i}. [{f.get('check_id','')}] {f.get('severity','')} — "
            f"{f.get('finding','')[:120]}"
        )
    return "\n".join(lines)


def _call_gemini(scores: dict[str, Any]) -> str | None:
    """Call gemini-1.5-flash for an executive summary. Returns text or None."""
    try:
        import google.generativeai as genai  # type: ignore

        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            return None

        genai.configure(api_key=api_key)

        overall_score = scores["overall_score"]
        maturity_band = scores["maturity_band"]
        by_sev = scores["by_severity"]
        critical_count = by_sev.get("CRITICAL", 0)
        high_count = by_sev.get("HIGH", 0)
        top_5 = _build_top_findings_text(scores.get("findings", []))

        prompt = f"""You are a senior Google Cloud security consultant writing \
an executive summary for a CISO. Be direct and specific.
Write exactly 4 sentences:
1. Overall security posture assessment
2. Most critical risk found and its business impact  
3. Second priority risk
4. Top recommendation

Data:
Overall score: {overall_score}/100
Maturity: {maturity_band}
Critical findings: {critical_count}
High findings: {high_count}
Top findings: {top_5}

Return plain text only. No markdown. No bullet points."""

        time.sleep(4)

        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        return response.text.strip()

    except Exception:  # noqa: BLE001
        return None


def _fallback_summary(scores: dict[str, Any]) -> str:
    overall = scores["overall_score"]
    maturity = scores["maturity_band"]
    by_sev = scores["by_severity"]
    c = by_sev.get("CRITICAL", 0)
    h = by_sev.get("HIGH", 0)
    return (
        f"This Google Cloud environment achieved an overall security score of {overall}/100, "
        f"placing it in the '{maturity}' maturity band and indicating significant gaps relative to "
        f"industry benchmarks. "
        f"The most critical risk identified is the presence of {c} CRITICAL findings — including "
        f"publicly accessible IAM bindings — which could allow unauthorised access to sensitive "
        f"cloud resources and result in data exfiltration or regulatory penalties. "
        f"Additionally, {h} HIGH-severity findings relate to over-privileged service accounts "
        f"and container workloads that lack security contexts, increasing the blast radius of "
        f"any successful compromise. "
        f"The top recommendation is to immediately remediate all CRITICAL IAM bindings by removing "
        f"'allUsers' and 'allAuthenticatedUsers' principals, then adopt Workload Identity Federation "
        f"to eliminate exported service account keys across the estate."
    )


# ---------------------------------------------------------------------------
# HTML builders
# ---------------------------------------------------------------------------

def _h(tag: str, text: str, style: str = "") -> str:
    s = f' style="{style}"' if style else ""
    return f"<{tag}{s}>{text}</{tag}>"


def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# Section 1 — Header
def _section_header(maturity: str, date_str: str) -> str:
    colour = _MATURITY_COLOUR.get(maturity, "#6b7280")
    badge = (
        f'<span style="background:{colour};color:#fff;border-radius:9999px;'
        f'padding:4px 14px;font-size:0.85rem;font-weight:600;letter-spacing:0.05em;">'
        f"{maturity}</span>"
    )
    return f"""
<div style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);
            color:#fff;padding:48px 40px;border-radius:12px;margin-bottom:32px;">
  <div style="font-size:0.8rem;letter-spacing:0.12em;text-transform:uppercase;
              color:#94a3b8;margin-bottom:8px;">Security Assessment</div>
  <h1 style="margin:0 0 6px;font-size:2rem;font-weight:700;letter-spacing:-0.02em;">
    CloudGuard — Cloud Security Posture Assessment
  </h1>
  <p style="margin:0 0 20px;font-size:1.05rem;color:#cbd5e1;">
    Automated Security Review Report
  </p>
  <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;">
    <span style="color:#94a3b8;font-size:0.9rem;">Generated: {date_str}</span>
    {badge}
  </div>
</div>
"""


# Section 2 — Executive summary
def _section_executive(summary_text: str) -> str:
    escaped = _escape(summary_text)
    return f"""
<section style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;
                padding:32px 36px;margin-bottom:28px;">
  <h2 style="margin:0 0 16px;font-size:1.3rem;font-weight:700;color:#0f172a;">
    Executive Summary
  </h2>
  <p style="margin:0;line-height:1.8;color:#334155;font-size:0.97rem;">
    {escaped}
  </p>
</section>
"""


# Section 3 — Score dashboard
def _score_bar(label: str, score: int) -> str:
    colour = _bar_colour(score)
    fill = max(score, 8)  # ensure label is readable even at low scores
    return f"""
<div style="margin-bottom:14px;">
  <div style="display:flex;justify-content:space-between;
              margin-bottom:4px;font-size:0.82rem;font-weight:600;
              color:#475569;text-transform:uppercase;letter-spacing:0.05em;">
    <span>{_escape(label)}</span>
  </div>
  <div style="background:#e2e8f0;border-radius:6px;height:30px;
              overflow:hidden;position:relative;">
    <div style="width:{fill}%;background:{colour};height:100%;
                border-radius:6px;transition:width 0.3s;
                display:flex;align-items:center;padding-left:10px;">
      <span style="color:#fff;font-weight:700;font-size:0.85rem;">{score}</span>
    </div>
  </div>
</div>
"""


def _section_scores(nist_scores: dict[str, int], zt_scores: dict[str, int]) -> str:
    nist_order = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    zt_order = ["Identity", "Workload", "Network", "Data", "DevOps"]

    nist_bars = "".join(
        _score_bar(fn, nist_scores.get(fn, 0)) for fn in nist_order
    )
    zt_bars = "".join(
        _score_bar(p, zt_scores.get(p, 0)) for p in zt_order
    )

    return f"""
<section style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;
                padding:32px 36px;margin-bottom:28px;">
  <h2 style="margin:0 0 24px;font-size:1.3rem;font-weight:700;color:#0f172a;">
    Score Dashboard
  </h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:32px;">
    <div>
      <h3 style="margin:0 0 14px;font-size:0.95rem;font-weight:700;
                 color:#475569;text-transform:uppercase;letter-spacing:0.07em;">
        NIST CSF Functions
      </h3>
      {nist_bars}
    </div>
    <div>
      <h3 style="margin:0 0 14px;font-size:0.95rem;font-weight:700;
                 color:#475569;text-transform:uppercase;letter-spacing:0.07em;">
        Zero Trust Pillars
      </h3>
      {zt_bars}
    </div>
  </div>
</section>
"""


# Section 4 — Findings tables (collapsible)
def _severity_badge(sev: str) -> str:
    style = _SEV_BADGE.get(sev.upper(), "background:#6b7280;color:#fff")
    return (
        f'<span style="{style};border-radius:4px;padding:2px 8px;'
        f'font-size:0.78rem;font-weight:700;">{_escape(sev)}</span>'
    )


def _findings_table(title: str, findings: list[dict]) -> str:
    if not findings:
        rows = '<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:16px;">No findings</td></tr>'
    else:
        sorted_f = sorted(
            findings,
            key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 4),
        )
        rows = ""
        for f in sorted_f:
            sev = f.get("severity", "LOW").upper()
            bg = _SEV_BG.get(sev, "#fff")
            rows += f"""
<tr style="background:{bg};">
  <td style="padding:8px 12px;font-size:0.82rem;font-weight:600;
             white-space:nowrap;">{_escape(f.get('check_id',''))}</td>
  <td style="padding:8px 12px;font-size:0.82rem;max-width:180px;
             word-break:break-word;">{_escape(f.get('resource',''))}</td>
  <td style="padding:8px 12px;font-size:0.82rem;">{_escape(f.get('finding',''))}</td>
  <td style="padding:8px 12px;font-size:0.82rem;
             white-space:nowrap;">{_severity_badge(sev)}</td>
  <td style="padding:8px 12px;font-size:0.82rem;">{_escape(f.get('recommendation',''))}</td>
  <td style="padding:8px 12px;font-size:0.82rem;
             white-space:nowrap;font-weight:600;color:#475569;">
    {_escape(f.get('nist_csf_function',''))}</td>
</tr>"""

    header_style = (
        "background:#0f172a;color:#fff;padding:8px 12px;"
        "font-size:0.78rem;text-transform:uppercase;letter-spacing:0.07em;"
        "text-align:left;"
    )
    count = len(findings)
    return f"""
<details style="border:1px solid #e2e8f0;border-radius:10px;
                margin-bottom:16px;overflow:hidden;">
  <summary style="background:#f8fafc;padding:18px 24px;cursor:pointer;
                  font-weight:700;font-size:1rem;color:#0f172a;
                  list-style:none;display:flex;justify-content:space-between;
                  align-items:center;">
    {_escape(title)}
    <span style="background:#334155;color:#fff;border-radius:9999px;
                 padding:2px 10px;font-size:0.8rem;">{count}</span>
  </summary>
  <div style="overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;font-family:inherit;">
      <thead>
        <tr>
          <th style="{header_style}">Check ID</th>
          <th style="{header_style}">Resource</th>
          <th style="{header_style}">Finding</th>
          <th style="{header_style}">Severity</th>
          <th style="{header_style}">Recommendation</th>
          <th style="{header_style}">NIST Function</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</details>
"""


def _section_findings(findings: list[dict]) -> str:
    # Group by scanner
    grouped: dict[str, list[dict]] = {}
    for f in findings:
        scanner = f.get("scanner", "unknown")
        grouped.setdefault(scanner, []).append(f)

    scanner_meta = {
        "gcp_iam": "GCP IAM Findings",
        "container": "Container Security Findings",
        "cicd": "CI/CD Pipeline Findings",
        "terraform": "Terraform Findings",
    }

    tables = ""
    for key, label in scanner_meta.items():
        tables += _findings_table(label, grouped.get(key, []))

    return f"""
<section style="margin-bottom:28px;">
  <h2 style="margin:0 0 20px;font-size:1.3rem;font-weight:700;color:#0f172a;">
    Findings by Scanner
  </h2>
  {tables}
</section>
"""


# Section 5 — GCP controls evaluated
def _section_controls() -> str:
    items = ""
    for i, (check_id, desc) in enumerate(_GCP_IAM_CHECKS, 1):
        items += f"""
<div style="display:flex;gap:12px;padding:12px 0;
            border-bottom:1px solid #f1f5f9;">
  <span style="font-weight:700;color:#475569;min-width:26px;">{i}.</span>
  <div>
    <span style="font-weight:700;color:#0f172a;font-family:monospace;
                 font-size:0.9rem;">{_escape(check_id)}</span>
    <span style="color:#334155;margin-left:8px;font-size:0.9rem;">{_escape(desc)}</span>
  </div>
</div>"""

    return f"""
<section style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;
                padding:32px 36px;margin-bottom:28px;">
  <h2 style="margin:0 0 4px;font-size:1.3rem;font-weight:700;color:#0f172a;">
    GCP IAM Controls Evaluated — Google Cloud Security Engineer Alignment
  </h2>
  <p style="margin:0 0 20px;font-size:0.87rem;color:#64748b;">
    Aligned with GCP Security Command Center findings and Google Cloud Security Foundations blueprint
  </p>
  {items}
</section>
"""


# Section 6 — Remediation priority list
def _section_remediation(findings: list[dict[str, Any]]) -> str:
    sorted_all: list[dict[str, Any]] = sorted(
        findings,
        key=lambda f: _SEV_ORDER.get(f.get("severity", "LOW"), 4),
    )
    top10 = sorted_all[:10]

    rows = ""
    for i, f in enumerate(top10, 1):
        sev = f.get("severity", "LOW").upper()
        eff = _effort(f.get("check_id", ""))
        effort_colour = {
            "Low": "#16a34a",
            "Med": "#d97706",
            "High": "#dc2626",
        }.get(eff, "#6b7280")
        rows += f"""
<tr style="border-bottom:1px solid #f1f5f9;">
  <td style="padding:10px 12px;font-weight:700;color:#0f172a;">{i}</td>
  <td style="padding:10px 12px;font-family:monospace;font-size:0.87rem;
             font-weight:600;">{_escape(f.get('check_id',''))}</td>
  <td style="padding:10px 12px;font-size:0.87rem;color:#334155;">
    {_escape(f.get('finding','')[:160])}</td>
  <td style="padding:10px 12px;">{_severity_badge(sev)}</td>
  <td style="padding:10px 12px;">
    <span style="color:{effort_colour};font-weight:700;font-size:0.85rem;">{eff}</span>
  </td>
  <td style="padding:10px 12px;font-size:0.82rem;color:#64748b;">High</td>
</tr>"""

    header_style = (
        "background:#f8fafc;padding:10px 12px;font-size:0.78rem;"
        "text-transform:uppercase;letter-spacing:0.06em;color:#475569;"
        "font-weight:700;text-align:left;border-bottom:2px solid #e2e8f0;"
    )
    return f"""
<section style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;
                padding:32px 36px;margin-bottom:28px;">
  <h2 style="margin:0 0 20px;font-size:1.3rem;font-weight:700;color:#0f172a;">
    Remediation Priority List — Top 10
  </h2>
  <div style="overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;font-family:inherit;">
      <thead>
        <tr>
          <th style="{header_style}">#</th>
          <th style="{header_style}">Check ID</th>
          <th style="{header_style}">Finding</th>
          <th style="{header_style}">Severity</th>
          <th style="{header_style}">Effort</th>
          <th style="{header_style}">Impact</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
"""


# ---------------------------------------------------------------------------
# Full HTML assembly
# ---------------------------------------------------------------------------

def _assemble_html(
    maturity: str,
    date_str: str,
    summary_text: str,
    nist_scores: dict[str, int],
    zt_scores: dict[str, int],
    overall_score: int,
    findings: list[dict],
) -> str:
    body = (
        _section_header(maturity, date_str)
        + _section_executive(summary_text)
        + _section_scores(nist_scores, zt_scores)
        + _section_findings(findings)
        + _section_controls()
        + _section_remediation(findings)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>CloudGuard Security Report — {date_str}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 32px;
      background: #f1f5f9;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                   'Helvetica Neue', Arial, sans-serif;
      color: #0f172a;
      line-height: 1.6;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    details > summary::-webkit-details-marker {{ display: none; }}
    details[open] > summary {{
      border-bottom: 1px solid #e2e8f0;
    }}
    @media (max-width: 768px) {{
      body {{ padding: 16px; }}
      .grid-2col {{ grid-template-columns: 1fr !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    {body}
    <footer style="text-align:center;color:#94a3b8;font-size:0.8rem;
                   padding:24px 0;border-top:1px solid #e2e8f0;margin-top:8px;">
      CloudGuard Security Reviewer · Generated {date_str} ·
      Aligned with NIST CSF 2.0 &amp; Zero Trust Architecture (NIST SP 800-207)
    </footer>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def generate_report(scores: dict[str, Any]) -> None:
    """
    Generate output/cloudguard_report.html from a scores dict.

    Parameters
    ----------
    scores : dict returned by scoring.nist_scorer.score()
        Required keys: overall_score, maturity_band, by_severity,
                       nist_scores, zt_scores, findings
    """
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    maturity = scores.get("maturity_band", "Initial")
    nist_scores: dict[str, int] = scores.get("nist_scores", {})
    zt_scores: dict[str, int] = scores.get("zt_scores", {})
    findings: list[dict] = scores.get("findings", [])

    # --- Executive summary (Gemini or fallback) ---
    print("  [report] Calling Gemini for executive summary …")
    summary = _call_gemini(scores)
    if summary:
        print("  [report] Gemini summary received.")
    else:
        print("  [report] Gemini unavailable — using fallback summary.")
        summary = _fallback_summary(scores)

    html = _assemble_html(
        maturity=maturity,
        date_str=date_str,
        summary_text=summary,
        nist_scores=nist_scores,
        zt_scores=zt_scores,
        overall_score=scores.get("overall_score", 0),
        findings=findings,
    )

    _OUTPUT_FILE.write_text(html, encoding="utf-8")
