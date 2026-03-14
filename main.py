"""
CloudGuard Security Reviewer — main entry-point
================================================
Runs all four scanners, scores findings against NIST CSF + Zero Trust,
then generates the consulting HTML report.

Usage:
    python main.py
"""

import os
import json
import time

from dotenv import load_dotenv

load_dotenv()
os.makedirs("output", exist_ok=True)

from scanners.gcp_iam_scanner import run as gcp_run
from scanners.container_scanner import run as container_run
from scanners.cicd_scanner import run as cicd_run
from scanners.terraform_scanner import run as tf_run
from scoring.nist_scorer import score
from report.report_generator import generate_report

print("[1/5] GCP IAM scan...")
gcp = gcp_run()
print(f"  {len(gcp)} findings")

print("[2/5] Container security scan...")
containers = container_run()
print(f"  {len(containers)} findings")

print("[3/5] CI/CD pipeline scan...")
cicd = cicd_run()
print(f"  {len(cicd)} findings")

print("[4/5] Terraform scan...")
tf = tf_run()
print(f"  {len(tf)} findings")

all_findings = gcp + containers + cicd + tf
print(f"\n[Scoring] Total findings: {len(all_findings)}")
scores = score(all_findings)
print(f"  Overall score: {scores['overall_score']}/100")
print(f"  Maturity: {scores['maturity_band']}")
print(f"  CRITICAL: {scores['by_severity']['CRITICAL']}")
print(f"  HIGH: {scores['by_severity']['HIGH']}")

# Persist scores.json alongside the HTML report
scores_path = os.path.join("output", "scores.json")
with open(scores_path, "w", encoding="utf-8") as fh:
    json.dump(scores, fh, indent=2)
print(f"\n  Scores written to {scores_path}")

print("\n[5/5] Generating consulting report...")
generate_report(scores)
print("  Report: output/cloudguard_report.html")
print("\nDone.")
