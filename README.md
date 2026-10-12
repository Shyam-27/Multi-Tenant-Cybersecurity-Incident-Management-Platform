# SentinelOps — Multi-Tenant Cybersecurity Incident Management Platform

SentinelOps is a production-grade, security-focused SaaS platform for managing cybersecurity incidents across isolated organizations. This repository implements **Phase 2: Backend Foundation, Database, Authentication, RBAC, and Multi-Tenant Security**.

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
                                              └──► Alembic Migrations
```

- **Frontend**: Vite 7, React 19, TypeScript 5.8, cybersecurity-themed operations dashboard.
- **Backend**: FastAPI 0.116, SQLAlchemy 2.0, Pydantic 2.14, Argon2id password hashing, PyJWT.
- **Database**: PostgreSQL 16 Alpine with Alembic migrations (`20261013_0003`).
- **Security**: Server-derived tenant context, RBAC authorization, constant-time authentication, IDOR mitigation (strict 404 policies on cross-tenant requests), token revocation.

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

## 4. Initial Tenant & Administrator Setup Procedure

SentinelOps does **not** hardcode default administrator credentials with predictable passwords.

To provision the initial organization and tenant administrator:

1. Navigate to the web application at [http://localhost:5173](http://localhost:5173) and select **"Register Organization"** (or use the API):
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "organization_name": "CyberCorp Security",
       "organization_slug": "cybercorp",
       "name": "Lead Administrator",
       "email": "admin@cybercorp.com",
       "password": "CorrectHorseBattery9!"
     }'
   ```
2. The registering user is atomically provisioned with the **`TENANT_ADMIN`** role for that organization.
3. Log in through the web portal or via `POST /api/v1/auth/login` to obtain an access token.
4. As `TENANT_ADMIN`, you can provision analysts (`SECURITY_ANALYST`) and viewers (`SECURITY_VIEWER`) within your organization via the dashboard or `/api/v1/users`.

---

## 5. Database Migrations

Migrations run automatically upon container startup (`alembic upgrade head`).

To inspect or execute migrations manually:

- **Check Current Migration**:
  ```powershell
  docker compose exec backend alembic current
  ```
- **Apply Head Migrations**:
  ```powershell
  docker compose exec backend alembic upgrade head
  ```
- **Roll Back One Revision**:
  ```powershell
  docker compose exec backend alembic downgrade -1
  ```

---

## 6. Running Automated Tests

All tests run in an isolated test environment with an in-memory SQLite database:

```powershell
docker compose exec backend pytest -v
```

The test suite covers:
- System and database health probes.
- User registration, duplicate rejection, and complexity checks.
- Timing-safe login and Argon2id hash storage.
- Protected route authentication, expired tokens, and logout revocation.
- RBAC permissions (analyst vs tenant admin capabilities).
- Multi-tenant isolation (Tenant A cannot view or modify Tenant B's users — returns 404).
- Anti-privilege escalation (preventing self-promotion and unauthorized `SUPER_ADMIN` assignment).
- User and tenant deactivation security.

---

## 7. Role-Based Access Control (RBAC) Matrix

See [docs/authorization.md](file:///d:/CyberSecurity_Incident_Managment_Platform/docs/authorization.md) for full authorization rules and access models:
- **`SUPER_ADMIN`**: Platform-wide administration.
- **`TENANT_ADMIN`**: Manage users and configuration within their tenant.
- **`SECURITY_ANALYST`**: Active incident triage and investigation.
- **`SECURITY_VIEWER`**: Read-only auditor view.

---

## 8. Common Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| `KeyError: 'formatters'` | Missing `[formatters]` section in an INI logging configuration file loaded by `fileConfig`. | Verified resolved. `alembic.ini` contains all logging sections, and `alembic/env.py` sets `disable_existing_loggers=False`. |
| `RuntimeError: Form data requires python-multipart` | Docker image was built before dependency was added to `requirements.txt`. | Rebuild backend image with `docker compose build backend`. |
| `503 Service Unavailable` on `/health` | PostgreSQL is not ready or connection parameters are incorrect. | Verify `docker compose ps` shows `postgres` healthy; check `DATABASE_URL` in `.env`. |
| `401 Unauthorized` on protected endpoints | Missing or expired token; token was revoked via `/logout`. | Log in again at `/api/v1/auth/login` to obtain a fresh JWT token. |
| `404 Not Found` when accessing user by ID | The requested user ID belongs to another organization (IDOR mitigation). | The user does not exist within the caller's tenant context. |
