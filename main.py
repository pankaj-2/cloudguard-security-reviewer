"""
CloudGuard Security Reviewer — main entry point

Workflow:
  1. Run all four scanner engines (GCP IAM, Container, CI/CD, Terraform)
  2. Score findings against the NIST CSF 2.0 framework
  3. (optional) Call Gemini for an AI-generated executive summary
  4. Generate a Markdown report and print it

Usage:
    python main.py

Environment:
    GEMINI_API_KEY — if set, enables Gemini AI executive summary
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Bootstrap: make sure the repo root is importable even when run from a
# different working directory.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


import config
from scanners import gcp_iam_scanner, container_scanner, cicd_scanner, terraform_scanner
from scoring import nist_scorer
from report import report_generator


# ---------------------------------------------------------------------------
# AI Executive Summary (Gemini)
# ---------------------------------------------------------------------------

def _gemini_summary(findings: list[dict], scores: dict) -> str | None:
    """
    Use the Gemini API to generate a concise executive summary.
    Returns None if the API key is missing or the call fails.
    """
    api_key = os.environ.get(config.GEMINI_API_KEY_ENV)
    if not api_key:
        print(
            f"[main] GEMINI_API_KEY not set — skipping AI summary. "
            f"Set the '{config.GEMINI_API_KEY_ENV}' environment variable to enable.",
            file=sys.stderr,
        )
        return None

    try:
        import google.generativeai as genai  # type: ignore[import]
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(config.GEMINI_MODEL)

        # Build a compact summary of the top findings to stay within token limits
        top_findings = sorted(
            findings,
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.get("severity", "LOW"), 4),
        )[:20]

        findings_text = "\n".join(
            f"[{f['severity']}] {f['check_id']} — {f['resource']}: {f['finding'][:120]}"
            for f in top_findings
        )

        prompt = f"""You are a senior cloud security architect producing an executive summary for a
security assessment report. Be direct, concise (≤ 250 words), and action-oriented.

Overall security score: {scores['overall_score']}/100
Risk tier: {scores['risk_tier']}
Total findings: {scores['total_findings']}

NIST CSF scores:
{chr(10).join(f"  {k}: {v}/100" for k, v in scores['function_scores'].items())}

Top findings:
{findings_text}

Write a 3‑paragraph executive summary:
1. Current security posture (1–2 sentences)
2. Most critical risks and their business impact (2–3 sentences)
3. Top 3 prioritised remediation actions (3 bullet points)
"""

        response = model.generate_content(prompt)
        return response.text.strip()

    except Exception as exc:  # pylint: disable=broad-except
        print(f"[main] Gemini AI summary failed: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("[main] Starting CloudGuard Security Review…")

    # 1. Run all scanners
    print("[main] Running GCP IAM scanner…")
    gcp_findings = gcp_iam_scanner.run()
    print(f"       → {len(gcp_findings)} finding(s)")

    print("[main] Running Container scanner…")
    container_findings = container_scanner.run()
    print(f"       → {len(container_findings)} finding(s)")

    print("[main] Running CI/CD scanner…")
    cicd_findings = cicd_scanner.run()
    print(f"       → {len(cicd_findings)} finding(s)")

    print("[main] Running Terraform scanner…")
    tf_findings = terraform_scanner.run()
    print(f"       → {len(tf_findings)} finding(s)")

    all_findings = gcp_findings + container_findings + cicd_findings + tf_findings
    print(f"[main] Total findings: {len(all_findings)}")

    # 2. Score against NIST CSF
    print("[main] Scoring against NIST CSF 2.0…")
    scores = nist_scorer.score(all_findings)
    print(f"       → Overall score: {scores['overall_score']}/100  |  Risk tier: {scores['risk_tier']}")

    # 3. AI executive summary (optional)
    print("[main] Requesting AI executive summary…")
    ai_summary = _gemini_summary(all_findings, scores)

    # 4. Generate report
    output_path = _REPO_ROOT / "security_report.md"
    print("[main] Generating Markdown report…")
    report = report_generator.generate(
        findings=all_findings,
        scores=scores,
        ai_summary=ai_summary,
        output_path=output_path,
    )

    # Print the report to stdout as well
    print("\n" + "=" * 72)
    print(report)
    print("=" * 72)
    print(f"\n[main] Done. Report saved to: {output_path}")


if __name__ == "__main__":
    main()
