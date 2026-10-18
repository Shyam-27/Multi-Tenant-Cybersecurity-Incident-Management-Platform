# SentinelOps — Multi-Tenant Cybersecurity Incident Management Platform

SentinelOps is a production-grade, security-focused SaaS platform for managing cybersecurity incidents across isolated organizations. This repository implements **Phase 7A: MFA, TOTP & Privileged-Action Security** and **Phase 7B: Durable Background Processing and Scheduled Jobs**.

---

## 1. Prerequisites

- **Docker Desktop** (version 24+ recommended, with WSL 2 backend on Windows)
- **Docker Compose v2**
- **Git**
- Optional for local non-container development: Python 3.12+, Node.js 22+

---

## 2. Architecture Overview

```text
Browser (React/TypeScript :5173) ──► FastAPI Backend (:8000) ──► PostgreSQL (:5432)
                                              │                    ▲
                                              ├──► Redis (:6379) ──┤ (Celery Broker)
                                              │         │          │
                                              │         ├─► Celery Worker (:concurrency 2)
                                              │         └─► Celery Beat (Scheduler)
                                              │
                                              ├──► Alembic Migrations (head: 20261018_0009)
                                              ├──► Append-Only Audit Trail (SHA-256 Hash Chain)
                                              ├──► Threat Intel Providers (VirusTotal, AbuseIPDB, OTX)
                                              ├──► SIEM Webhook Dispatcher (Splunk, Elastic, Teams, Slack)
                                              ├──► Durable Background Worker (Retry, Backoff, Jitter)
                                              ├──► Incident Response Playbooks Engine
                                              └──► Tenant Storage (uploads/{tenant_id}/...)
```

- **Frontend**: Vite 8.3, React 19, TypeScript 5.8, SOC operations dashboard with incident metrics, filtering, detail drawer, timeline notes, digital evidence artifacts, an Immutable Audit Trail log viewer, Threat Intelligence IOC explorer with multi-provider breakdown and background enrich queueing, SIEM webhook integration manager with live test pings, delivery retry actions, and Response Playbooks executor with approval workflows and Step-Up MFA.
- **Backend**: FastAPI 0.116, SQLAlchemy 2.0, Pydantic 2.14, Argon2id password hashing, PyJWT HS256 tokens, streaming file validation, append-only audit recording service with cryptographic SHA-256 chaining, threat intelligence caching & aggregation engine, SSRF-safe webhook dispatcher, dual-authorization response playbook engine, and Celery 5.4 distributed worker with Redis 7 broker.
- **Database**: PostgreSQL 16 Alpine with Alembic migrations (`20261018_0009`).
- **Distributed Cache & Broker**: Redis 7 Alpine with AOF persistence.
- **Security**: Server-derived tenant context, strict RBAC authorization, constant-time authentication, IDOR mitigation (strict 404 policies on cross-tenant requests), token revocation, state-machine transition validation, streaming magic-byte signature inspection, SHA-256 integrity verification, SSRF blocking of private IP ranges/cloud metadata, anti-privilege escalation, anti-self-approval dual authorization, TOTP multi-factor authentication with encrypted secret storage, and append-only audit logging with cryptographic chain integrity checks.

---

## 3. Quick Start with Docker Compose

1. **Configure Environment Variables**:
   Copy `.env.example` to `.env`:
   ```powershell
   cp .env.example .env
   ```
   *Ensure `POSTGRES_PASSWORD` and `JWT_SECRET_KEY` are configured with secure values in `.env`.*

2. **Build and Start Services**:
   ```powershell
   docker compose up -d --build
   ```

3. **Verify Service Health**:
   - Web Application: [http://localhost:5173](http://localhost:5173)
   - API Root Health: [http://localhost:8000/health](http://localhost:8000/health)
   - API v1 Health: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)
   - OpenAPI / Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
   - ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

4. **Stop Services**:
   ```powershell
   docker compose down
   ```
   *(Do not pass `-v` unless you intentionally want to delete the persistent PostgreSQL volume `postgres_data`).*

---

## 4. Initial Setup & Workflow

1. **Register Organization**:
   Navigate to [http://localhost:5173](http://localhost:5173) or call `POST /api/v1/auth/register` to register an organization and initial `TENANT_ADMIN`.
2. **Provision Analysts & Viewers**:
   Using the Team Directory dashboard or `POST /api/v1/users`, provision analysts (`SECURITY_ANALYST`) or viewers (`SECURITY_VIEWER`).
3. **Report Incidents**:
   Call `POST /api/v1/incidents` to publish a security incident with category, severity, and optional assigned analyst. Automatically dispatches alerts to registered SIEM destinations.
4. **Investigate & Triage**:
   Transition status (`OPEN` → `INVESTIGATING` → `CONTAINED` → `RESOLVED` → `CLOSED`), update severities or assignees, and append investigation notes with `POST /api/v1/incidents/{id}/notes`.
5. **Manage Evidence**:
   Upload digital forensic artifacts (PCAP, PCAPNG, ZIP, TAR, GZ, TXT, LOG, JSON, CSV) with incremental SHA-256 hashing and download with enforced `X-Content-Type-Options: nosniff`.
6. **Threat Intelligence Feeds & IOC Enrichment**:
   Query and record indicators of compromise (IPv4, IPv6, domains, URLs, hashes). Enrich against VirusTotal v3, AbuseIPDB v2, and AlienVault OTX with 24-hour cache TTL.
7. **SIEM & Webhook Alerting**:
   Configure notification endpoints for Splunk HEC, Elastic SIEM, MS Teams, and Slack. Execute live test pings and inspect delivery history.
8. **Automated Response Playbooks**:
   Execute simulated or live response playbooks (credential revocation, endpoint isolation, IP blocklist) with dual-authorization approval workflow and anti-self-approval enforcement.
9. **Audit & Verify Security Trail**:
   Inspect security events under the SOC Audit Trail tab. Verify cryptographic hash chain integrity via `GET /api/v1/audit-events/verify-chain`.

---

## 5. API Endpoints

| Endpoint | Method | Role Allowed | Description |
|---|---|---|---|
| `/api/v1/incidents/metrics` | GET | All authenticated | Aggregated metric counters for dashboard. |
| `/api/v1/incidents` | GET | All authenticated | Paginated, filtered, tenant-scoped incident list. |
| `/api/v1/incidents` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Publish new incident (derives creator and tenant). |
| `/api/v1/incidents/{id}` | GET | All authenticated | View incident details, notes, and evidence (404 on cross-tenant). |
| `/api/v1/incidents/{id}` | PATCH | `TENANT_ADMIN`, `SECURITY_ANALYST` | Update severity, status (state machine checked), or assignee. |
| `/api/v1/incidents/{id}/notes` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Append chronological investigation note. |
| `/api/v1/incidents/{id}/evidence` | GET | All authenticated | List evidence artifacts attached to incident. |
| `/api/v1/incidents/{id}/evidence` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Upload evidence artifact (max 10 MiB, magic byte validated). |
| `/api/v1/auth/mfa/enroll` | POST | All authenticated | Initiate TOTP enrollment (returns QR code & recovery codes). |
| `/api/v1/auth/mfa/confirm-enroll` | POST | All authenticated | Verify first TOTP code and activate MFA for account. |
| `/api/v1/auth/mfa/status` | GET | All authenticated | Inspect MFA status and remaining unused recovery codes. |
| `/api/v1/auth/mfa/disable` | POST | All authenticated | Disable MFA (requires password and current TOTP). |
| `/api/v1/auth/mfa/recovery-codes/regenerate` | POST | All authenticated | Invalidate and generate 10 new recovery codes. |
| `/api/v1/auth/mfa/verify-login` | POST | Public (challenge token) | Complete 2-stage login with TOTP or recovery code. |
| `/api/v1/auth/mfa/step-up` | POST | All authenticated | Issue short-lived Step-Up token for privileged action. |
| `/api/v1/incidents/{id}/evidence/{eid}/download` | GET | All authenticated | Download evidence artifact (`nosniff`, tenant-isolated). |
| `/api/v1/iocs` | GET | All authenticated | List/search tenant Indicators of Compromise. |
| `/api/v1/iocs` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Record new normalized IOC. |
| `/api/v1/iocs/{id}/enrich` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Query threat intelligence providers and update verdict. |
| `/api/v1/iocs/{id}/enrich-async` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Enqueue non-blocking background threat intelligence refresh (202 Accepted). |
| `/api/v1/destinations` | GET | All authenticated | List registered SIEM and webhook destinations. |
| `/api/v1/destinations` | POST | `TENANT_ADMIN`, `SUPER_ADMIN` | Register webhook destination (SSRF protected). |
| `/api/v1/destinations/{id}/test` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Dispatch synthetic test alert and record delivery log. |
| `/api/v1/destinations/deliveries` | GET | All authenticated | Tenant-scoped webhook delivery attempt audit logs. |
| `/api/v1/destinations/deliveries/{id}/retry` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Manually re-enqueue a failed or retrying webhook delivery attempt. |
| `/api/v1/jobs` | GET | All authenticated | Tenant-scoped background job execution status list. |
| `/api/v1/jobs/{id}` | GET | All authenticated | Inspect specific background job status and result summary (404 on cross-tenant). |
| `/api/v1/playbooks` | GET | All authenticated | List configured response playbooks. |
| `/api/v1/playbooks/{id}/execute` | POST | `TENANT_ADMIN`, `SECURITY_ANALYST` | Trigger playbook execution (Step-Up MFA required for live actions). |
| `/api/v1/playbooks/executions/{id}/approve` | POST | `TENANT_ADMIN`, `SUPER_ADMIN` | Dual-authorization approval (Step-Up MFA required for live actions). |
| `/api/v1/audit-events` | GET | All authenticated | Paginated, filtered audit events (tenant-isolated). |
| `/api/v1/audit-events/verify-chain` | GET | `TENANT_ADMIN`, `SUPER_ADMIN` | Cryptographic SHA-256 chain verification. |

---

## 6. Database Migrations

Migrations execute automatically upon container startup (`alembic upgrade head`).

- **Inspect Current Revision**:
  ```powershell
  docker compose exec backend alembic current
  ```
  *(Expected: `20261018_0009 (head)`)*
- **Apply Migrations**:
  ```powershell
  docker compose exec backend alembic upgrade head
  ```
- **Rollback One Revision**:
  ```powershell
  docker compose exec backend alembic downgrade -1
  ```

---

## 7. Running Automated Tests

Run the full pytest suite in the isolated test environment:

```powershell
docker compose exec backend pytest -q
```

**130 automated test cases** cover:
- Health probes and database connectivity.
- Authentication, Argon2id hashing, and JWT lifecycle/logout revocation.
- TOTP Multi-Factor Authentication (RFC 6238), provisioning URI, self-contained SVG QR codes.
- Authenticated AES-GCM/Fernet encryption of TOTP secrets at rest (`MFA_ENCRYPTION_KEY`).
- Two-stage login with scoped challenge token and credential isolation.
- Single-use hashed backup recovery codes with row-locked atomic consumption.
- Anti-replay defense on TOTP time steps (`last_totp_timestep`).
- Brute-force account lockout protection (5 failed attempts = 15-minute lock).
- Step-Up MFA for live response playbook execution and live playbook approval (`X-MFA-Code`, `X-Step-Up-Token`).
- RBAC permissions (Super Admin, Tenant Admin, Analyst, Viewer).
- User management and anti-privilege escalation.
- Multi-tenant data isolation on users, incidents, notes, evidence, audit logs, IOCs, destinations, background jobs, and playbooks (strict 404 policy).
- Incident CRUD, server-derived tenant context, filters, and pagination.
- Status transition state-machine validation and timestamp handling.
- Cross-tenant analyst assignment rejection (400).
- Digital evidence upload, size enforcement, magic byte signatures, SHA-256 calculation, and nosniff downloads.
- Audit event persistence, actor and tenant attribution, login tracking, incident & evidence audit recording, pagination, query filters, hash chain verification, and database tampering detection.
- IOC normalization, validation, deduplication, mock provider lookups (VirusTotal, AbuseIPDB), caching TTL, and false-positive flags.
- Webhook SSRF validation (blocking loopback, RFC1918, cloud metadata), destination management, synthetic ping, and incident dispatch integration.
- Durable Celery + Redis background processing: intent persisted before worker ack (`PENDING`), row locking (`locked_at`, `locked_by`), transient vs. permanent error classification, exponential backoff with bounded jitter, max 5 attempts to terminal failure, recovery beat worker for stuck/pending deliveries, broker outage resilience, and dispatch-time SSRF revalidation prohibiting redirects.
- Background IOC threat intelligence refresh: non-blocking async endpoint, periodic scheduled refresh, anti-tampering verdict preservation (provider outages never become BENIGN).
- Playbook dry-run simulation, credential revocation, anti-privilege escalation, loopback shield, dual-authorization approval, and anti-self-approval rejection.

---

## 8. Role-Based Access Control (RBAC) Matrix

See [docs/authorization.md](file:///d:/CyberSecurity_Incident_Managment_Platform/docs/authorization.md) for full authorization rules and access models:
- **`SUPER_ADMIN`**: Platform-wide administration and audit access.
- **`TENANT_ADMIN`**: Manage users, organization settings, incidents, playbooks, destinations, and verify tenant audit chains.
- **`SECURITY_ANALYST`**: Incident triage, status transitions, notes, evidence upload/download, IOC enrichment, and simulated playbook triggering.
- **`SECURITY_VIEWER`**: Read-only auditor view of incidents, notes, evidence, metrics, audit events, IOCs, and playbooks.
