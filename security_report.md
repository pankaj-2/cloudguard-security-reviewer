# CloudGuard Security Report

**Generated:** 2026-03-14 12:00 UTC
**Risk Tier:** CRITICAL
**Overall Security Score:** 72/100
**Total Findings:** 97

---

## Executive Summary


*No AI summary available. Set GEMINI_API_KEY to enable Gemini-powered analysis.*


---

## NIST CSF Score Breakdown

| Function   | Score |
|------------|-------|
| IDENTIFY   | 96/100 |
| PROTECT    | 0/100 |
| DETECT     | 66/100 |
| RESPOND    | 100/100 |
| RECOVER    | 98/100 |


---

## Severity Breakdown

| Severity | Count |
|----------|-------|
| CRITICAL | 16 |
| HIGH     | 54 |
| MEDIUM   | 24 |
| LOW      | 3 |


---

## Findings


### GCP_IAM Scanner (37 finding(s))


#### [GCP-001] CRITICAL — roles/owner → allUsers

**Finding:** Public member 'allUsers' is granted 'roles/owner'. This exposes the resource to the entire internet or all Google accounts.

**Recommendation:** Remove 'allUsers' and 'allAuthenticatedUsers' from all IAM bindings. Replace with specific user, service-account, or group principals.

**NIST CSF:** PROTECT

---

#### [GCP-001] CRITICAL — roles/owner → allUsers

**Finding:** Public member 'allUsers' is granted 'roles/owner'. This exposes the resource to the entire internet or all Google accounts.

**Recommendation:** Remove 'allUsers' and 'allAuthenticatedUsers' from all IAM bindings. Replace with specific user, service-account, or group principals.

**NIST CSF:** PROTECT

---

#### [GCP-001] CRITICAL — roles/owner → allAuthenticatedUsers

**Finding:** Public member 'allAuthenticatedUsers' is granted 'roles/owner'. This exposes the resource to the entire internet or all Google accounts.

**Recommendation:** Remove 'allUsers' and 'allAuthenticatedUsers' from all IAM bindings. Replace with specific user, service-account, or group principals.

**NIST CSF:** PROTECT

---

#### [GCP-002] HIGH — roles/owner → user:developer@company.com

**Finding:** Human user 'user:developer@company.com' holds the Owner role at project scope. Owner grants unrestricted access to all resources and IAM policies.

**Recommendation:** Remove Owner from human users. Grant least-privilege roles such as roles/editor or specific resource roles. Use groups rather than individual accounts for administrative access.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:test-sa@myproject.iam.gserviceaccount.com / key:key001

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:temp-migration-sa@myproject.iam.gserviceaccount.com / key:key002

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:db-client@myproject.iam.gserviceaccount.com / key:key003

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:legacy-api-sa@myproject.iam.gserviceaccount.com / key:key004

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:stale-batch-sa@myproject.iam.gserviceaccount.com / key:key005

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:etl-runner@myproject.iam.gserviceaccount.com / key:key006

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:monitoring-sa@myproject.iam.gserviceaccount.com / key:key007

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:deploy-agent@myproject.iam.gserviceaccount.com / key:key008

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-003] HIGH — serviceAccount:gcs-backup-sa@myproject.iam.gserviceaccount.com / key:key009

**Finding:** This service account has a user-managed (exported) key. Exported keys leave GCP's security perimeter and increase credential theft risk.

**Recommendation:** Delete the exported key and migrate to Workload Identity Federation. If keys are unavoidable, store them in Secret Manager with rotation enforced.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:test-sa@myproject.iam.gserviceaccount.com / key:key001

**Finding:** Service account key has not been rotated in 1048 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:temp-migration-sa@myproject.iam.gserviceaccount.com / key:key002

**Finding:** Service account key has not been rotated in 1154 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:db-client@myproject.iam.gserviceaccount.com / key:key003

**Finding:** Service account key has not been rotated in 916 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:legacy-api-sa@myproject.iam.gserviceaccount.com / key:key004

**Finding:** Service account key has not been rotated in 1118 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:stale-batch-sa@myproject.iam.gserviceaccount.com / key:key005

**Finding:** Service account key has not been rotated in 1321 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:etl-runner@myproject.iam.gserviceaccount.com / key:key006

**Finding:** Service account key has not been rotated in 1368 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:monitoring-sa@myproject.iam.gserviceaccount.com / key:key007

**Finding:** Service account key has not been rotated in 1443 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:deploy-agent@myproject.iam.gserviceaccount.com / key:key008

**Finding:** Service account key has not been rotated in 794 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-004] HIGH — serviceAccount:gcs-backup-sa@myproject.iam.gserviceaccount.com / key:key009

**Finding:** Service account key has not been rotated in 739 days (threshold: 90 days). Stale keys increase the blast radius of credential compromise.

**Recommendation:** Rotate service account keys at least every 90 days. Prefer Workload Identity Federation to eliminate the need for long-lived keys.

**NIST CSF:** PROTECT

---

#### [GCP-007] HIGH — roles/editor → serviceAccount:app-sa@myproject.iam.gserviceaccount.com

**Finding:** 'serviceAccount:app-sa@myproject.iam.gserviceaccount.com' holds the Editor role at project scope. Editor grants read/write access to most GCP services and violates least-privilege.

**Recommendation:** Replace roles/editor with purpose-specific roles (e.g., roles/storage.objectAdmin, roles/cloudsql.editor). Apply roles at the minimum required resource scope.

**NIST CSF:** PROTECT

---

#### [GCP-007] HIGH — roles/editor → user:backend-dev@company.com

**Finding:** 'user:backend-dev@company.com' holds the Editor role at project scope. Editor grants read/write access to most GCP services and violates least-privilege.

**Recommendation:** Replace roles/editor with purpose-specific roles (e.g., roles/storage.objectAdmin, roles/cloudsql.editor). Apply roles at the minimum required resource scope.

**NIST CSF:** PROTECT

---

#### [GCP-007] HIGH — roles/editor → user:intern@company.com

**Finding:** 'user:intern@company.com' holds the Editor role at project scope. Editor grants read/write access to most GCP services and violates least-privilege.

**Recommendation:** Replace roles/editor with purpose-specific roles (e.g., roles/storage.objectAdmin, roles/cloudsql.editor). Apply roles at the minimum required resource scope.

**NIST CSF:** PROTECT

---

#### [GCP-007] HIGH — roles/editor → group:engineering@company.com

**Finding:** 'group:engineering@company.com' holds the Editor role at project scope. Editor grants read/write access to most GCP services and violates least-privilege.

**Recommendation:** Replace roles/editor with purpose-specific roles (e.g., roles/storage.objectAdmin, roles/cloudsql.editor). Apply roles at the minimum required resource scope.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:test-sa@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:temp-migration-sa@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:db-client@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:legacy-api-sa@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:stale-batch-sa@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:etl-runner@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:monitoring-sa@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:deploy-agent@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-005] MEDIUM — serviceAccount:gcs-backup-sa@myproject.iam.gserviceaccount.com

**Finding:** Service account uses key-based authentication and has no Workload Identity Federation binding configured. Key-based auth requires managing long-lived secrets.

**Recommendation:** Configure Workload Identity Federation and remove exported keys. WIF allows workloads to impersonate service accounts without downloading key files.

**NIST CSF:** PROTECT

---

#### [GCP-006] MEDIUM — serviceAccount:test-sa@myproject.iam.gserviceaccount.com

**Finding:** Service account 'test-sa@myproject.iam.gserviceaccount.com' (display: 'test account for integration testing') has test/temporary naming conventions suggesting it was created for development or testing and should not exist in a production environment.

**Recommendation:** Audit test and temporary service accounts. Delete or disable those not required in production. Enforce a naming policy to prevent test accounts entering prod.

**NIST CSF:** IDENTIFY

---

#### [GCP-006] MEDIUM — serviceAccount:temp-migration-sa@myproject.iam.gserviceaccount.com

**Finding:** Service account 'temp-migration-sa@myproject.iam.gserviceaccount.com' (display: 'temp migration helper') has test/temporary naming conventions suggesting it was created for development or testing and should not exist in a production environment.

**Recommendation:** Audit test and temporary service accounts. Delete or disable those not required in production. Enforce a naming policy to prevent test accounts entering prod.

**NIST CSF:** IDENTIFY

---


### CONTAINER Scanner (33 finding(s))


#### [CONTAINER-001] CRITICAL — docker-compose/service:admin-tools

**Finding:** Service 'admin-tools' runs as a privileged container (privileged: true). Privileged mode grants full host access.

**Recommendation:** Remove 'privileged: true'. Use specific Linux capabilities (cap_add) for only what is needed. Prefer rootless containers and AppArmor/seccomp profiles.

**NIST CSF:** PROTECT

---

#### [CONTAINER-002] CRITICAL — docker-compose/service:network-utils

**Finding:** Service 'network-utils' uses host network mode. This bypasses container network isolation.

**Recommendation:** Remove 'network_mode: host'. Use bridge networking with explicit port mappings instead.

**NIST CSF:** PROTECT

---

#### [CONTAINER-004] CRITICAL — docker-compose/service:admin-tools/volume:/etc/passwd:/etc/passwd:ro

**Finding:** Service 'admin-tools' mounts host path '/etc/passwd' into the container. This path is sensitive and may expose system files.

**Recommendation:** Replace host path mounts with named Docker volumes. For system-level access, evaluate whether it is strictly necessary and apply read-only mounts where possible.

**NIST CSF:** PROTECT

---

#### [CONTAINER-001] CRITICAL — k8s/Deployment:vulnerable-app/container:sidecar-agent

**Finding:** Container 'sidecar-agent' in Deployment 'vulnerable-app' is privileged. Privileged K8s containers can escape to the host.

**Recommendation:** Set 'securityContext.privileged: false'. Use specific capabilities (capabilities.add) for only what is required.

**NIST CSF:** PROTECT

---

#### [CONTAINER-002] CRITICAL — k8s/Deployment:vulnerable-app

**Finding:** Deployment 'vulnerable-app' has hostNetwork: true. Pods share the host network namespace, bypassing network isolation.

**Recommendation:** Set 'hostNetwork: false' or remove the field. Use ClusterIP services and ingress controllers instead of direct host networking.

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — docker-compose/service:admin-tools/env:ADMIN_TOKEN

**Finding:** Service 'admin-tools' has a potential hardcoded secret in environment variable 'ADMIN_TOKEN'.

**Recommendation:** Remove hardcoded credentials from docker-compose files. Use Docker Secrets, environment variable files (.env), or a secret manager (e.g., Vault, AWS Secrets Manager).

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — docker-compose/service:postgres/env:POSTGRES_PASSWORD

**Finding:** Service 'postgres' has a potential hardcoded secret in environment variable 'POSTGRES_PASSWORD'.

**Recommendation:** Remove hardcoded credentials from docker-compose files. Use Docker Secrets, environment variable files (.env), or a secret manager (e.g., Vault, AWS Secrets Manager).

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — docker-compose/service:api-service/env:API_KEY

**Finding:** Service 'api-service' has a potential hardcoded secret in environment variable 'API_KEY'.

**Recommendation:** Remove hardcoded credentials from docker-compose files. Use Docker Secrets, environment variable files (.env), or a secret manager (e.g., Vault, AWS Secrets Manager).

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — docker-compose/service:api-service/env:DB_PASSWORD

**Finding:** Service 'api-service' has a potential hardcoded secret in environment variable 'DB_PASSWORD'.

**Recommendation:** Remove hardcoded credentials from docker-compose files. Use Docker Secrets, environment variable files (.env), or a secret manager (e.g., Vault, AWS Secrets Manager).

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — docker-compose/service:api-service/env:JWT_SECRET

**Finding:** Service 'api-service' has a potential hardcoded secret in environment variable 'JWT_SECRET'.

**Recommendation:** Remove hardcoded credentials from docker-compose files. Use Docker Secrets, environment variable files (.env), or a secret manager (e.g., Vault, AWS Secrets Manager).

**NIST CSF:** PROTECT

---

#### [CONTAINER-006] HIGH — docker-compose/service:admin-tools

**Finding:** Service 'admin-tools' has no 'user' directive. Containers run as root (UID 0) by default.

**Recommendation:** Add 'user: "<uid>:<gid>"' to the service definition. Use a non-root UID (e.g., 1000:1000). Ensure the base image supports running as non-root.

**NIST CSF:** PROTECT

---

#### [CONTAINER-006] HIGH — docker-compose/service:network-utils

**Finding:** Service 'network-utils' has no 'user' directive. Containers run as root (UID 0) by default.

**Recommendation:** Add 'user: "<uid>:<gid>"' to the service definition. Use a non-root UID (e.g., 1000:1000). Ensure the base image supports running as non-root.

**NIST CSF:** PROTECT

---

#### [CONTAINER-006] HIGH — docker-compose/service:postgres

**Finding:** Service 'postgres' has no 'user' directive. Containers run as root (UID 0) by default.

**Recommendation:** Add 'user: "<uid>:<gid>"' to the service definition. Use a non-root UID (e.g., 1000:1000). Ensure the base image supports running as non-root.

**NIST CSF:** PROTECT

---

#### [CONTAINER-006] HIGH — docker-compose/service:api-service

**Finding:** Service 'api-service' has no 'user' directive. Containers run as root (UID 0) by default.

**Recommendation:** Add 'user: "<uid>:<gid>"' to the service definition. Use a non-root UID (e.g., 1000:1000). Ensure the base image supports running as non-root.

**NIST CSF:** PROTECT

---

#### [CONTAINER-006] HIGH — docker-compose/service:web-proxy

**Finding:** Service 'web-proxy' has no 'user' directive. Containers run as root (UID 0) by default.

**Recommendation:** Add 'user: "<uid>:<gid>"' to the service definition. Use a non-root UID (e.g., 1000:1000). Ensure the base image supports running as non-root.

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — k8s/Deployment:vulnerable-app/container:main-app/env:DB_PASSWORD

**Finding:** Container 'main-app' has a potential hardcoded secret in env var 'DB_PASSWORD'.

**Recommendation:** Use Kubernetes Secrets with secretKeyRef or a secrets manager (e.g., Vault, AWS Secrets Manager with CSI driver). Never store credentials as plaintext in manifests.

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — k8s/Deployment:vulnerable-app/container:main-app/env:API_KEY

**Finding:** Container 'main-app' has a potential hardcoded secret in env var 'API_KEY'.

**Recommendation:** Use Kubernetes Secrets with secretKeyRef or a secrets manager (e.g., Vault, AWS Secrets Manager with CSI driver). Never store credentials as plaintext in manifests.

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — k8s/Deployment:vulnerable-app/container:main-app/env:JWT_SECRET

**Finding:** Container 'main-app' has a potential hardcoded secret in env var 'JWT_SECRET'.

**Recommendation:** Use Kubernetes Secrets with secretKeyRef or a secrets manager (e.g., Vault, AWS Secrets Manager with CSI driver). Never store credentials as plaintext in manifests.

**NIST CSF:** PROTECT

---

#### [CONTAINER-003] HIGH — k8s/Deployment:vulnerable-app/container:sidecar-agent/env:DD_API_KEY

**Finding:** Container 'sidecar-agent' has a potential hardcoded secret in env var 'DD_API_KEY'.

**Recommendation:** Use Kubernetes Secrets with secretKeyRef or a secrets manager (e.g., Vault, AWS Secrets Manager with CSI driver). Never store credentials as plaintext in manifests.

**NIST CSF:** PROTECT

---

#### [CONTAINER-005] HIGH — k8s/Deployment:vulnerable-app/container:main-app

**Finding:** Container 'main-app' in Deployment 'vulnerable-app' has no securityContext. Container will inherit permissive defaults.

**Recommendation:** Define a securityContext with at minimum: allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, runAsNonRoot: true, and capabilities.drop: [ALL].

**NIST CSF:** PROTECT

---

#### [CONTAINER-005] HIGH — k8s/Deployment:vulnerable-app/container:log-forwarder

**Finding:** Container 'log-forwarder' in Deployment 'vulnerable-app' has no securityContext. Container will inherit permissive defaults.

**Recommendation:** Define a securityContext with at minimum: allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, runAsNonRoot: true, and capabilities.drop: [ALL].

**NIST CSF:** PROTECT

---

#### [CONTAINER-006] HIGH — k8s/Deployment:vulnerable-app/container:sidecar-agent

**Finding:** Container 'sidecar-agent' in Deployment 'vulnerable-app' explicitly sets runAsUser: 0 (root). Root containers can escalate to host.

**Recommendation:** Set runAsUser to a non-zero UID (e.g., 1000). Add runAsNonRoot: true to the pod securityContext as an additional guard.

**NIST CSF:** PROTECT

---

#### [CONTAINER-009] HIGH — k8s/ClusterRoleBinding:app-admin-binding/subject:app-service-account

**Finding:** ClusterRoleBinding 'app-admin-binding' grants 'cluster-admin' to 'ServiceAccount:app-service-account'. This provides cluster-wide privileged access.

**Recommendation:** Replace cluster-admin with narrowly scoped Roles and RoleBindings limited to specific namespaces and verbs. Apply least-privilege RBAC using the principle of minimal required access.

**NIST CSF:** PROTECT

---

#### [CONTAINER-010] HIGH — k8s/ServiceAccount:default/app-service-account

**Finding:** ServiceAccount 'default/app-service-account' has automountServiceAccountToken: true and is bound to a broad RBAC role. Any pod using this SA automatically receives a high-privilege token.

**Recommendation:** Set 'automountServiceAccountToken: false' on the ServiceAccount and opt-in per-pod only where required. Restrict the bound role to minimal required permissions.

**NIST CSF:** PROTECT

---

#### [CONTAINER-007] MEDIUM — docker-compose/service:admin-tools/image:busybox:latest

**Finding:** Service 'admin-tools' uses unpinned image tag 'busybox:latest'. :latest is mutable and may pull a different image silently.

**Recommendation:** Pin images to an immutable digest: 'image: myimage:v1.2.3@sha256:<digest>'. Use image scanning in CI/CD to validate pinned images.

**NIST CSF:** PROTECT

---

#### [CONTAINER-007] MEDIUM — docker-compose/service:network-utils/image:nicolaka/netshoot:latest

**Finding:** Service 'network-utils' uses unpinned image tag 'nicolaka/netshoot:latest'. :latest is mutable and may pull a different image silently.

**Recommendation:** Pin images to an immutable digest: 'image: myimage:v1.2.3@sha256:<digest>'. Use image scanning in CI/CD to validate pinned images.

**NIST CSF:** PROTECT

---

#### [CONTAINER-007] MEDIUM — docker-compose/service:web-proxy/image:nginx:latest

**Finding:** Service 'web-proxy' uses unpinned image tag 'nginx:latest'. :latest is mutable and may pull a different image silently.

**Recommendation:** Pin images to an immutable digest: 'image: myimage:v1.2.3@sha256:<digest>'. Use image scanning in CI/CD to validate pinned images.

**NIST CSF:** PROTECT

---

#### [CONTAINER-004] MEDIUM — k8s/Deployment:vulnerable-app/volume:varlog

**Finding:** Deployment 'vulnerable-app' mounts host path '/var/log' via hostPath volume. This grants container access to host filesystem data.

**Recommendation:** Replace hostPath volumes with PersistentVolumeClaims backed by a storage class. For log access use sidecar log-forwarder patterns.

**NIST CSF:** PROTECT

---

#### [CONTAINER-007] MEDIUM — k8s/Deployment:vulnerable-app/container:main-app/image:myapp:latest

**Finding:** Container 'main-app' uses unpinned image 'myapp:latest'. Mutable tags can lead to unintended image upgrades.

**Recommendation:** Pin images to a SHA256 digest: 'image: myimage:v1.2.3@sha256:<hash>'. Enforce digest pinning via admission controller or OPA policy.

**NIST CSF:** PROTECT

---

#### [CONTAINER-007] MEDIUM — k8s/Deployment:vulnerable-app/container:sidecar-agent/image:datadog/agent:latest

**Finding:** Container 'sidecar-agent' uses unpinned image 'datadog/agent:latest'. Mutable tags can lead to unintended image upgrades.

**Recommendation:** Pin images to a SHA256 digest: 'image: myimage:v1.2.3@sha256:<hash>'. Enforce digest pinning via admission controller or OPA policy.

**NIST CSF:** PROTECT

---

#### [CONTAINER-008] MEDIUM — k8s/Deployment:vulnerable-app/container:main-app

**Finding:** Container 'main-app' in Deployment 'vulnerable-app' is missing CPU and/or memory resource limits. Unbounded containers risk resource exhaustion (DoS).

**Recommendation:** Define both 'resources.limits.cpu' and 'resources.limits.memory'. Also set 'resources.requests' to aid scheduler placement. Consider LimitRange objects to enforce defaults cluster-wide.

**NIST CSF:** PROTECT

---

#### [CONTAINER-008] MEDIUM — k8s/Deployment:vulnerable-app/container:sidecar-agent

**Finding:** Container 'sidecar-agent' in Deployment 'vulnerable-app' is missing CPU and/or memory resource limits. Unbounded containers risk resource exhaustion (DoS).

**Recommendation:** Define both 'resources.limits.cpu' and 'resources.limits.memory'. Also set 'resources.requests' to aid scheduler placement. Consider LimitRange objects to enforce defaults cluster-wide.

**NIST CSF:** PROTECT

---

#### [CONTAINER-008] MEDIUM — k8s/Deployment:vulnerable-app/container:log-forwarder

**Finding:** Container 'log-forwarder' in Deployment 'vulnerable-app' is missing CPU and/or memory resource limits. Unbounded containers risk resource exhaustion (DoS).

**Recommendation:** Define both 'resources.limits.cpu' and 'resources.limits.memory'. Also set 'resources.requests' to aid scheduler placement. Consider LimitRange objects to enforce defaults cluster-wide.

**NIST CSF:** PROTECT

---


### CICD Scanner (14 finding(s))


#### [CICD-003] CRITICAL — job:build/step:Debug API credentials

**Finding:** Step 'Debug API credentials' echoes a secret to the runner log. Even with log masking, secrets may leak via encoding tricks.

**Recommendation:** Remove debug echo statements referencing ${{ secrets.* }}. Use '::add-mask::' only for dynamic values if absolutely needed.

**NIST CSF:** DETECT

---

#### [CICD-003] CRITICAL — job:docker-build/step:Login to Docker Hub

**Finding:** Step 'Login to Docker Hub' echoes a secret to the runner log. Even with log masking, secrets may leak via encoding tricks.

**Recommendation:** Remove debug echo statements referencing ${{ secrets.* }}. Use '::add-mask::' only for dynamic values if absolutely needed.

**NIST CSF:** DETECT

---

#### [CICD-003] CRITICAL — job:deploy/step:Configure kubectl

**Finding:** Step 'Configure kubectl' echoes a secret to the runner log. Even with log masking, secrets may leak via encoding tricks.

**Recommendation:** Remove debug echo statements referencing ${{ secrets.* }}. Use '::add-mask::' only for dynamic values if absolutely needed.

**NIST CSF:** DETECT

---

#### [CICD-001] HIGH — workflow:permissions

**Finding:** Workflow permissions set to 'write-all'. Grants write access to all repository scopes.

**Recommendation:** Replace 'permissions: write-all' with explicit minimal permissions per-job.

**NIST CSF:** PROTECT

---

#### [CICD-002] HIGH — job:build/step:Checkout code

**Finding:** Action 'actions/checkout@v2' is not pinned to a full commit SHA. Tags are mutable and can be updated to malicious commits (supply-chain attack vector).

**Recommendation:** Pin to a full SHA: 'uses: actions/checkout@<40-char-sha>'. Use Dependabot or pin-github-action to automate pinning.

**NIST CSF:** PROTECT

---

#### [CICD-002] HIGH — job:build/step:Setup Node

**Finding:** Action 'actions/setup-node@v3' is not pinned to a full commit SHA. Tags are mutable and can be updated to malicious commits (supply-chain attack vector).

**Recommendation:** Pin to a full SHA: 'uses: actions/setup-node@<40-char-sha>'. Use Dependabot or pin-github-action to automate pinning.

**NIST CSF:** PROTECT

---

#### [CICD-002] HIGH — job:build/step:Upload coverage

**Finding:** Action 'codecov/codecov-action@v1' is not pinned to a full commit SHA. Tags are mutable and can be updated to malicious commits (supply-chain attack vector).

**Recommendation:** Pin to a full SHA: 'uses: codecov/codecov-action@<40-char-sha>'. Use Dependabot or pin-github-action to automate pinning.

**NIST CSF:** PROTECT

---

#### [CICD-002] HIGH — job:docker-build/step:actions/checkout@v2

**Finding:** Action 'actions/checkout@v2' is not pinned to a full commit SHA. Tags are mutable and can be updated to malicious commits (supply-chain attack vector).

**Recommendation:** Pin to a full SHA: 'uses: actions/checkout@<40-char-sha>'. Use Dependabot or pin-github-action to automate pinning.

**NIST CSF:** PROTECT

---

#### [CICD-002] HIGH — job:deploy/step:actions/checkout@v2

**Finding:** Action 'actions/checkout@v2' is not pinned to a full commit SHA. Tags are mutable and can be updated to malicious commits (supply-chain attack vector).

**Recommendation:** Pin to a full SHA: 'uses: actions/checkout@<40-char-sha>'. Use Dependabot or pin-github-action to automate pinning.

**NIST CSF:** PROTECT

---

#### [CICD-005] MEDIUM — workflow/env:ACTIONS_RUNNER_DEBUG

**Finding:** Debug flag 'ACTIONS_RUNNER_DEBUG' is permanently enabled. Debug mode may dump environment variables and secret values to the run log.

**Recommendation:** Remove 'ACTIONS_RUNNER_DEBUG' from the YAML. Enable via repository secret on a per-run basis.

**NIST CSF:** DETECT

---

#### [CICD-005] MEDIUM — workflow/env:ACTIONS_STEP_DEBUG

**Finding:** Debug flag 'ACTIONS_STEP_DEBUG' is permanently enabled. Debug mode may dump environment variables and secret values to the run log.

**Recommendation:** Remove 'ACTIONS_STEP_DEBUG' from the YAML. Enable via repository secret on a per-run basis.

**NIST CSF:** DETECT

---

#### [CICD-006] LOW — job:build

**Finding:** Job 'build' has no 'timeout-minutes'. A hung job consumes runner minutes until GitHub's 6-hour default — a cost/resource risk.

**Recommendation:** Add 'timeout-minutes: <N>' to each job. Most jobs should complete in < 30 min.

**NIST CSF:** PROTECT

---

#### [CICD-006] LOW — job:docker-build

**Finding:** Job 'docker-build' has no 'timeout-minutes'. A hung job consumes runner minutes until GitHub's 6-hour default — a cost/resource risk.

**Recommendation:** Add 'timeout-minutes: <N>' to each job. Most jobs should complete in < 30 min.

**NIST CSF:** PROTECT

---

#### [CICD-006] LOW — job:deploy

**Finding:** Job 'deploy' has no 'timeout-minutes'. A hung job consumes runner minutes until GitHub's 6-hour default — a cost/resource risk.

**Recommendation:** Add 'timeout-minutes: <N>' to each job. Most jobs should complete in < 30 min.

**NIST CSF:** PROTECT

---


### TERRAFORM Scanner (13 finding(s))


#### [TF-001] CRITICAL — google_project_iam_binding.public_owner

**Finding:** IAM binding grants 'roles/owner' to public member 'allUsers'. This exposes your project to the entire internet or all Google accounts.

**Recommendation:** Remove 'allUsers' and 'allAuthenticatedUsers' from all IAM bindings. Replace with specific principals (user:, serviceAccount:, group:).

**NIST CSF:** PROTECT

---

#### [TF-001] CRITICAL — google_project_iam_binding.public_owner

**Finding:** IAM binding grants 'roles/owner' to public member 'allAuthenticatedUsers'. This exposes your project to the entire internet or all Google accounts.

**Recommendation:** Remove 'allUsers' and 'allAuthenticatedUsers' from all IAM bindings. Replace with specific principals (user:, serviceAccount:, group:).

**NIST CSF:** PROTECT

---

#### [TF-003] CRITICAL — google_compute_firewall.allow_all_ingress

**Finding:** Firewall rule 'allow_all_ingress' allows all TCP ports from 0.0.0.0/0 (the entire internet). This creates a very large attack surface.

**Recommendation:** Restrict source_ranges to known IP ranges and limit allowed ports to only those required. Use firewall tags and VPC Service Controls to reduce scope.

**NIST CSF:** PROTECT

---

#### [TF-008] CRITICAL — google_project_iam_binding.public_owner → allUsers

**Finding:** Principal 'allUsers' is granted 'roles/owner' at project scope. Owner grants unrestricted access to GCP resources.

**Recommendation:** Replace 'roles/owner' with purpose-specific predefined or custom roles. Apply at the minimum necessary resource scope (not project-wide).

**NIST CSF:** PROTECT

---

#### [TF-008] CRITICAL — google_project_iam_binding.public_owner → allAuthenticatedUsers

**Finding:** Principal 'allAuthenticatedUsers' is granted 'roles/owner' at project scope. Owner grants unrestricted access to GCP resources.

**Recommendation:** Replace 'roles/owner' with purpose-specific predefined or custom roles. Apply at the minimum necessary resource scope (not project-wide).

**NIST CSF:** PROTECT

---

#### [TF-002] HIGH — google_service_account_key.deploy_sa_key

**Finding:** Terraform creates an exported service account key. Key material leaves GCP's security perimeter and is stored in Terraform state (often plaintext).

**Recommendation:** Delete the google_service_account_key resource and migrate to Workload Identity Federation. If keys are unavoidable, store in Secret Manager with rotation.

**NIST CSF:** PROTECT

---

#### [TF-004] HIGH — google_storage_bucket.app_data

**Finding:** Bucket 'app_data' has uniform_bucket_level_access disabled. Object-level ACLs can bypass bucket IAM policies, leading to over-permissive access.

**Recommendation:** Set 'uniform_bucket_level_access = true'. Migrate any object ACLs to bucket-level IAM policies beforehand.

**NIST CSF:** PROTECT

---

#### [TF-006] HIGH — google_compute_instance.app_server

**Finding:** Instance 'app_server' uses the 'cloud-platform' scope, which grants the instance's service account access to all Google Cloud APIs.

**Recommendation:** Replace 'cloud-platform' with specific API scopes (e.g., 'storage.read_only', 'logging.write'). Apply least privilege at both the scope and IAM role level.

**NIST CSF:** PROTECT

---

#### [TF-008] HIGH — google_project_iam_binding.broad_editor → user:developer@company.com

**Finding:** Principal 'user:developer@company.com' is granted 'roles/editor' at project scope. Editor grants unrestricted access to GCP resources.

**Recommendation:** Replace 'roles/editor' with purpose-specific predefined or custom roles. Apply at the minimum necessary resource scope (not project-wide).

**NIST CSF:** PROTECT

---

#### [TF-008] HIGH — google_project_iam_binding.broad_editor → user:contractor@external.com

**Finding:** Principal 'user:contractor@external.com' is granted 'roles/editor' at project scope. Editor grants unrestricted access to GCP resources.

**Recommendation:** Replace 'roles/editor' with purpose-specific predefined or custom roles. Apply at the minimum necessary resource scope (not project-wide).

**NIST CSF:** PROTECT

---

#### [TF-008] HIGH — google_project_iam_binding.broad_editor → group:engineering@company.com

**Finding:** Principal 'group:engineering@company.com' is granted 'roles/editor' at project scope. Editor grants unrestricted access to GCP resources.

**Recommendation:** Replace 'roles/editor' with purpose-specific predefined or custom roles. Apply at the minimum necessary resource scope (not project-wide).

**NIST CSF:** PROTECT

---

#### [TF-005] MEDIUM — google_compute_instance.app_server

**Finding:** Instance 'app_server' has OS Login disabled (enable-oslogin = false). Without OS Login, SSH access falls back to project/instance SSH keys which are harder to audit and revoke.

**Recommendation:** Set 'enable-oslogin = "true"' in the instance metadata block. OS Login integrates with Cloud IAM for centralized SSH key management.

**NIST CSF:** PROTECT

---

#### [TF-007] MEDIUM — google_storage_bucket.app_data

**Finding:** Bucket 'app_data' does not have versioning enabled. Accidental or malicious deletions/overwrites cannot be recovered.

**Recommendation:** Add 'versioning { enabled = true }' to the bucket. Combine with Object Lifecycle rules to manage storage costs.

**NIST CSF:** RECOVER

---


