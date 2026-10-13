# SentinelOps — Multi-Tenant Cybersecurity Incident Management Platform

SentinelOps is a production-grade, security-focused SaaS platform for managing cybersecurity incidents across isolated organizations. This repository implements **Phase 5: Immutable Audit Trail & Security Event Monitoring**.

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
                                              │
                                              ├──► Alembic Migrations
                                              ├──► Append-Only Audit Trail (SHA-256 Hash Chain)
                                              └──► Tenant Storage (uploads/{tenant_id}/...)
```

- **Frontend**: Vite 8.3, React 19, TypeScript 5.8, SOC operations dashboard with incident metrics, filtering, detail drawer, timeline notes, digital evidence artifacts, and an Immutable Audit Trail log viewer with on-demand hash chain verification.
- **Backend**: FastAPI 0.116, SQLAlchemy 2.0, Pydantic 2.14, Argon2id password hashing, PyJWT HS256 tokens, streaming file validation, append-only audit recording service with cryptographic SHA-256 chaining.
- **Database**: PostgreSQL 16 Alpine with Alembic migrations (`20261013_0006`).
- **Security**: Server-derived tenant context, strict RBAC authorization, constant-time authentication, IDOR mitigation (strict 404 policies on cross-tenant requests), token revocation, state-machine transition validation, streaming magic-byte signature inspection, SHA-256 integrity verification, safe path resolution, and append-only audit logging with cryptographic chain integrity checks.

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
   Call `POST /api/v1/incidents` to publish a security incident with category, severity, and optional assigned analyst.
4. **Investigate & Triage**:
   Transition status (`OPEN` → `INVESTIGATING` → `CONTAINED` → `RESOLVED` → `CLOSED`), update severities or assignees, and append investigation notes with `POST /api/v1/incidents/{id}/notes`.
5. **Manage Evidence**:
   Upload digital forensic artifacts (PCAP, PCAPNG, ZIP, TAR, GZ, TXT, LOG, JSON, CSV) with incremental SHA-256 hashing and download with enforced `X-Content-Type-Options: nosniff`.
6. **Audit & Verify Security Trail**:
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
| `/api/v1/incidents/{id}/evidence/{eid}/download` | GET | All authenticated | Download evidence artifact (`nosniff`, tenant-isolated). |
| `/api/v1/audit-events` | GET | All authenticated | Paginated, filtered audit events (tenant-isolated). |
| `/api/v1/audit-events/verify-chain` | GET | `TENANT_ADMIN`, `SUPER_ADMIN` | Cryptographic SHA-256 chain verification. |
| `/api/v1/audit-events/{id}` | GET | All authenticated | Single audit event details (404 anti-IDOR). |

### Audit & Security Event Monitoring
- **Append-Only Enforcement**: No update (`PUT`/`PATCH`) or deletion (`DELETE`) endpoints are exposed.
- **SHA-256 Hash Chaining**: Every audit event links to its predecessor via `previous_hash` and generates an `event_hash` over canonically sorted JSON metadata.
- **Automatic Secret Redaction**: Credentials, password hashes, and bearer tokens are automatically replaced with `[REDACTED]`.
- **Security Signal Detection**: Records security events on login failures, cross-tenant resource probing, privilege escalation attempts, and evidence validation violations.

---

## 6. Database Migrations

Migrations execute automatically upon container startup (`alembic upgrade head`).

- **Inspect Current Revision**:
  ```powershell
  docker compose exec backend alembic current
  ```
  *(Expected: `20261013_0006 (head)`)*
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
docker compose exec backend pytest -v
```

**72 automated test cases** cover:
- Health probes and database connectivity.
- Authentication, Argon2id hashing, and JWT lifecycle/logout revocation.
- RBAC permissions (Super Admin, Tenant Admin, Analyst, Viewer).
- User management and anti-privilege escalation.
- Multi-tenant data isolation on users, incidents, notes, evidence, and audit logs (strict 404 policy).
- Incident CRUD, server-derived tenant context, filters, and pagination.
- Status transition state-machine validation and timestamp handling.
- Cross-tenant analyst assignment rejection (400).
- Protection of immutable fields (`tenant_id`, `created_by_id`, `created_at`).
- Digital evidence upload, size enforcement, magic byte signatures, SHA-256 calculation, and nosniff downloads.
- Audit event persistence, actor and tenant attribution, login tracking, incident & evidence audit recording, pagination, query filters, hash chain verification, and database tampering detection.

---

## 8. Role-Based Access Control (RBAC) Matrix

See [docs/authorization.md](file:///d:/CyberSecurity_Incident_Managment_Platform/docs/authorization.md) for full authorization rules and access models:
- **`SUPER_ADMIN`**: Platform-wide administration and audit access.
- **`TENANT_ADMIN`**: Manage users, organization settings, incidents, and verify tenant audit chains.
- **`SECURITY_ANALYST`**: Incident triage, status transitions, notes, and evidence upload/download.
- **`SECURITY_VIEWER`**: Read-only auditor view of incidents, notes, evidence, metrics, and audit events.
