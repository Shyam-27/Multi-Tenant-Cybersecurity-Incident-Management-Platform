# SentinelOps — Multi-Tenant Cybersecurity Incident Management Platform

SentinelOps is a production-grade, security-focused SaaS platform for managing cybersecurity incidents across isolated organizations. This repository implements **Phase 4: Digital Evidence Management & Secure File Uploads**.

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
                                              └──► Tenant Storage (uploads/{tenant_id}/...)
```

- **Frontend**: Vite 8.3, React 19, TypeScript 5.8, SOC operations dashboard with incident metrics, filtering, detail drawer, investigation timeline notes, and digital evidence artifacts.
- **Backend**: FastAPI 0.116, SQLAlchemy 2.0, Pydantic 2.14, Argon2id password hashing, PyJWT HS256 tokens, streaming file validation and hashing.
- **Database**: PostgreSQL 16 Alpine with Alembic migrations (`20261013_0005`).
- **Security**: Server-derived tenant context, strict RBAC authorization, constant-time authentication, IDOR mitigation (strict 404 policies on cross-tenant requests), token revocation, state-machine transition validation, streaming magic-byte signature inspection, SHA-256 integrity verification, safe path resolution, and `nosniff` streaming downloads.

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

---

## 5. Incident & Evidence Management Endpoints

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

### Evidence Security Controls
- **File Allowlist**: `.log`, `.txt`, `.json`, `.csv`, `.pcap`, `.pcapng`, `.zip`, `.tar`, `.gz`, `.tgz`.
- **Magic Byte Verification**: Inspects file headers to enforce formats (e.g. PCAP headers `\xd4\xc3\xb2\xa1`, PCAPNG `\x0a\x0d\x0d\x0a`, ZIP `PK\x03\x04`, GZIP `\x1f\x8b`, text UTF-8 checks) and strictly blocks executable binaries (`MZ`, `\x7fELF`).
- **Streaming Validation & Size Enforcement**: 10 MiB maximum limit checked chunk-by-chunk during upload.
- **Integrity**: Incremental SHA-256 calculation stored in the database.
- **Tenant Path Isolation**: Files stored at `uploads/{tenant_id}/{incident_id}/{evidence_id}/{filename}` with path traversal protection.

---

## 6. Database Migrations

Migrations execute automatically upon container startup (`alembic upgrade head`).

- **Inspect Current Revision**:
  ```powershell
  docker compose exec backend alembic current
  ```
  *(Expected: `20261013_0005 (head)`)*
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

**54 automated test cases** cover:
- Health probes and database connectivity.
- Authentication, Argon2id hashing, and JWT lifecycle/logout revocation.
- RBAC permissions (Super Admin, Tenant Admin, Analyst, Viewer).
- User management and anti-privilege escalation.
- Multi-tenant data isolation on users, incidents, notes, and evidence (strict 404 policy).
- Incident CRUD, server-derived tenant context, filters, and pagination.
- Status transition state-machine validation and timestamp handling.
- Cross-tenant analyst assignment rejection (400).
- Protection of immutable fields (`tenant_id`, `created_by_id`, `created_at`).
- Digital evidence upload, size enforcement, magic byte signatures, SHA-256 calculation, and nosniff downloads.

---

## 8. Role-Based Access Control (RBAC) Matrix

See [docs/authorization.md](file:///d:/CyberSecurity_Incident_Managment_Platform/docs/authorization.md) for full authorization rules and access models:
- **`SUPER_ADMIN`**: Platform-wide administration.
- **`TENANT_ADMIN`**: Manage users, organization settings, and incidents within their tenant.
- **`SECURITY_ANALYST`**: Active incident triage, investigation, status transitions, and notes.
- **`SECURITY_VIEWER`**: Read-only auditor view of incidents, notes, and metrics.
