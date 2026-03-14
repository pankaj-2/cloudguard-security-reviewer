# CloudGuard Project State

## Completed

- [x] Phase 1: Structure + mock data

## Next

Phase 2: Scanner engines

## All files written

### Package init files
- `scanners/__init__.py`
- `scoring/__init__.py`
- `report/__init__.py`

### Scanner stubs (empty, logic in Phase 2)
- `scanners/gcp_iam_scanner.py`
- `scanners/container_scanner.py`
- `scanners/cicd_scanner.py`
- `scanners/terraform_scanner.py`

### Scoring stub (empty, logic in Phase 2)
- `scoring/nist_scorer.py`

### Report stub (empty, logic in Phase 2)
- `report/report_generator.py`

### Application files
- `config.py` — USE_MOCK_DATA, GEMINI_API_KEY_ENV, GEMINI_MODEL constants
- `main.py` — empty entrypoint stub
- `requirements.txt` — google-generativeai, python-dotenv, pyyaml, python-hcl2, jinja2

### Mock input data (examples/)
- `examples/gcp_iam_policy.json` — 20 IAM bindings; 2×CRITICAL allUsers owner, 1×HIGH human owner, 3×HIGH editor, 2×MEDIUM securityAdmin, rest safe
- `examples/gcp_service_accounts.json` — 15 service accounts; 4 with USER_MANAGED keys, 3 stale (>90d), 5 no workload identity, 2 test/temp named, 4 properly configured
- `examples/docker-compose.yml` — privileged:true, network_mode:host, hardcoded DB_PASSWORD & API_KEY, /etc/passwd mount, :latest images, root containers
- `examples/k8s_deployment.yaml` — missing securityContext, privileged sidecar, hostNetwork:true, no resource limits, SA token auto-mount with admin ClusterRole, hardcoded secrets in env
- `examples/github_actions_workflow.yml` — permissions:write-all, pull_request_target injection risk, secrets echoed in logs, non-SHA-pinned actions, ACTIONS_RUNNER_DEBUG:true, no timeout-minutes
- `examples/main.tf` — allUsers owner binding, google_service_account_key export, enable-oslogin=false, uniform_bucket_level_access=false, 0.0.0.0/0 firewall

### Project metadata
- `PROJECT_STATE.md` — this file

## Phase 2 Scope (upcoming)

Scanner engines to implement:
1. `scanners/gcp_iam_scanner.py` — parse gcp_iam_policy.json + gcp_service_accounts.json → Finding objects
2. `scanners/container_scanner.py` — parse docker-compose.yml + k8s_deployment.yaml → Finding objects
3. `scanners/cicd_scanner.py` — parse github_actions_workflow.yml → Finding objects
4. `scanners/terraform_scanner.py` — parse main.tf → Finding objects
5. `scoring/nist_scorer.py` — map findings to NIST CSF controls + severity scoring
6. `report/report_generator.py` — Jinja2 → Markdown/HTML report
7. `main.py` — wire everything together, call Gemini for AI-assisted analysis
