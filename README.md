# CloudGuard — Cloud Security Posture Reviewer

## What it does
Automated cloud security assessment tool that scans GCP IAM 
policies, container configurations, CI/CD pipelines, and 
Terraform files to produce a consulting-grade security 
maturity report — the same deliverable format used in 
Google Cloud security engagement reviews.

## Why this exists
Built to demonstrate security review and maturity assessment 
skills aligned with the Google Cloud Security Engineer role:
conducting security reviews across technology stacks, 
providing risk findings with recommendations, and assessing 
Zero Trust maturity during cloud/DevOps transformation.

## Scanners included
- GCP IAM scanner — 7 controls (service accounts, bindings, 
  Workload Identity, Owner role exposure)
- Container scanner — 10 controls (Docker Compose + K8s 
  manifests: privileged containers, RBAC, secrets in env)
- CI/CD scanner — 6 controls (GitHub Actions: 
  secret exposure, unpinned actions, injection risks)
- Terraform scanner — 5 controls (GCP IaC misconfigurations)

## GCP IAM controls evaluated
(Aligned with Google Cloud Security Foundations blueprint 
and Security Command Center findings)

1. GCP-001: allUsers / allAuthenticatedUsers IAM bindings
2. GCP-002: Human users with Owner role at project level
3. GCP-003: Exported user-managed service account keys
4. GCP-004: Service account keys not rotated >90 days
5. GCP-005: Service accounts without Workload Identity
6. GCP-006: Test/temp service accounts in production
7. GCP-007: Editor role at project scope

## Scoring methodology
- NIST CSF 5-function scores (Identify/Protect/Detect/
  Respond/Recover)
- Zero Trust 5-pillar scores (Identity/Workload/Network/
  Data/DevOps) per NIST SP 800-207
- Maturity bands: Initial / Developing / Defined / Optimising
- GenAI executive summary via Gemini 1.5 Flash (free tier)

## Quick start
```bash
pip install -r requirements.txt
cp .env.example .env   # add GEMINI_API_KEY from aistudio.google.com
python main.py
# Report: output/cloudguard_report.html
```

## Tech stack
Python · PyYAML · python-hcl2 · 
Google Gemini 1.5 Flash API (free tier) ·
Mock data matching GCP Resource Manager + IAM API shapes

## Sample output
```
Overall score: 42/100 — Developing
CRITICAL findings: 4
HIGH findings: 8  
Report: single self-contained HTML file, no dependencies
```

## JD alignment — Google Security Engineer
- Security reviews and maturity assessments ✓
- GCP cloud security controls ✓
- Container and microservice security ✓
- DevOps/CI-CD security risks ✓
- Zero Trust architecture assessment ✓
- Consulting-style deliverable for clients ✓
