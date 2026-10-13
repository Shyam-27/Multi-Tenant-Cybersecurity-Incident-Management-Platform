# SentinelOps Authorization & RBAC Specification

## 1. Overview

SentinelOps enforces strict server-side Role-Based Access Control (RBAC) and multi-tenant isolation. All access decisions are evaluated on the backend using validated JWT credentials and database relationships. Client-provided tenant identifiers are never trusted for authorization or resource scoping.

---

## 2. Platform Roles

| Role | Scope | Description |
|---|---|---|
| `SUPER_ADMIN` | Platform-wide | Platform-level administrator. Manages tenants, system configurations, and cross-tenant audits. Not bound to a single tenant (`tenant_id = null` or system tenant). |
| `TENANT_ADMIN` | Tenant-scoped | Organization administrator. Manages users, organization settings, and security assignments within their own tenant organization. Full incident management rights. |
| `SECURITY_ANALYST` | Tenant-scoped | Active incident responder. Creates, analyzes, updates, and triages security incidents within their own tenant organization. Can append investigation notes. |
| `SECURITY_VIEWER` | Tenant-scoped | Read-only auditor or executive. Views incidents, notes, and metrics within their tenant organization. Cannot modify records, add notes, or manage users. |

---

## 3. Permission Matrix

| Resource / Endpoint | HTTP Method | `SUPER_ADMIN` | `TENANT_ADMIN` | `SECURITY_ANALYST` | `SECURITY_VIEWER` |
|---|---|---|---|---|---|
| `/health`, `/api/v1/health` | GET | Allowed | Allowed | Allowed | Allowed |
| `/api/v1/auth/register` | POST | Public | Public | Public | Public |
| `/api/v1/auth/login` | POST | Public | Public | Public | Public |
| `/api/v1/auth/me` | GET | Allowed | Allowed | Allowed | Allowed |
| `/api/v1/auth/logout` | POST | Allowed | Allowed | Allowed | Allowed |
| `/api/v1/auth/change-password` | POST | Allowed | Allowed | Allowed | Allowed |
| `/api/v1/tenants/me` | GET | Allowed (if associated) | Allowed (Own Org) | Allowed (Own Org) | Allowed (Own Org) |
| `/api/v1/users` | GET | Allowed (All/Filtered) | Allowed (Own Org) | **Forbidden (403)** | **Forbidden (403)** |
| `/api/v1/users` (Provision) | POST | Allowed | Allowed (Own Org only) | **Forbidden (403)** | **Forbidden (403)** |
| `/api/v1/users/{id}` (View) | GET | Allowed | Allowed (Own Org) | Allowed (Own Org) | Allowed (Own Org) |
| `/api/v1/users/{id}` (Update) | PATCH | Allowed | Allowed (Own Org) | **Forbidden (403)** | **Forbidden (403)** |
| Cross-tenant `/users/{id}` | GET/PATCH | Allowed | **Not Found (404)** | **Not Found (404)** | **Not Found (404)** |
| Self-role modification | PATCH | Forbidden (403) | **Forbidden (403)** | **Forbidden (403)** | **Forbidden (403)** |
| Escalation to `SUPER_ADMIN` | POST/PATCH | Allowed | **Forbidden (403)** | **Forbidden (403)** | **Forbidden (403)** |
| `/api/v1/incidents` (List/Search) | GET | Allowed (All/Filtered) | Allowed (Own Org) | Allowed (Own Org) | Allowed (Own Org) |
| `/api/v1/incidents/metrics` | GET | Allowed (All/Filtered) | Allowed (Own Org) | Allowed (Own Org) | Allowed (Own Org) |
| `/api/v1/incidents` (Create) | POST | Allowed | Allowed (Own Org) | Allowed (Own Org) | **Forbidden (403)** |
| `/api/v1/incidents/{id}` (View) | GET | Allowed | Allowed (Own Org) | Allowed (Own Org) | Allowed (Own Org) |
| `/api/v1/incidents/{id}` (Update) | PATCH | Allowed | Allowed (Own Org) | Allowed (Own Org) | **Forbidden (403)** |
| `/api/v1/incidents/{id}/notes` | POST | Allowed | Allowed (Own Org) | Allowed (Own Org) | **Forbidden (403)** |
| Cross-tenant `/incidents/{id}` | GET/PATCH/NOTES | Allowed | **Not Found (404)** | **Not Found (404)** | **Not Found (404)** |

---

## 4. Incident Status Workflow & Transition Rules

Incidents adhere to a centralized state machine enforced in `app/services/incident_service.py`.

```text
[ OPEN ] ──► [ INVESTIGATING ] ──┬──► [ CONTAINED ] ──┬──► [ RESOLVED ] ──► [ CLOSED ]
                   ▲             │         │          │         │
                   │             └─────────┴──────────┘         │
                   │                                            │
                   └───────────────── (Reopen) ─────────────────┘
```

| Current Status | Allowed Next Statuses | Notes |
|---|---|---|
| `OPEN` | `INVESTIGATING` | Initial triage state. |
| `INVESTIGATING` | `CONTAINED`, `RESOLVED` | Active investigation. |
| `CONTAINED` | `INVESTIGATING`, `RESOLVED` | Threat mitigated; moving to recovery or root cause. |
| `RESOLVED` | `INVESTIGATING` (reopen), `CLOSED` | Sets `resolved_at` UTC timestamp. Reopening clears `resolved_at`. |
| `CLOSED` | *(None - Terminal)* | Final archived state. Invalid transitions return `409 Conflict`. |

---

## 5. Multi-Tenant Isolation & Anti-IDOR Principles

1. **Server-Derived Context**:
   - The authenticated user's `tenant_id` is extracted strictly from the validated JWT token and the verified `User` record in PostgreSQL.
   - Any client-submitted `tenant_id` or `created_by_id` in request payloads is disregarded.

2. **Consistent 404 on Cross-Tenant Inquiries**:
   - To mitigate Insecure Direct Object References (IDOR / BOLA) and prevent organization resource enumeration, requests targeting an incident or user belonging to another tenant respond with `404 Not Found` (rather than `403 Forbidden`).
   - This ensures an attacker cannot determine whether an identifier exists in another organization.

3. **Analyst Assignment Validation**:
   - When assigning an incident (`assigned_to_id`), the server verifies that the assignee belongs to the *same* tenant, has an active account, and possesses either the `SECURITY_ANALYST` or `TENANT_ADMIN` role. Cross-tenant assignments are rejected with `400 Bad Request`.

4. **Self-Role Modification Prevention**:
   - A `TENANT_ADMIN` cannot alter their own `role` field on `/api/v1/users/{id}`. This prevents accidental lockout or illegitimate privilege transitions.

5. **Privilege Escalation Prevention**:
   - `TENANT_ADMIN` can only create or assign roles within `{TENANT_ADMIN, SECURITY_ANALYST, SECURITY_VIEWER}`.
   - Any attempt by a `TENANT_ADMIN` to create or promote a user to `SUPER_ADMIN` is rejected with `403 Forbidden`.

6. **Lifecycle Status Enforcement**:
   - Deactivated users (`is_active = false`) are rejected at credential verification and on every authenticated request with `401 Unauthorized`.
   - Deactivated tenants (`is_active = false`) invalidate access for all member users with `403 Forbidden` (`Organization is deactivated`).

7. **Token Revocation (Logout)**:
   - When `/api/v1/auth/logout` is called, the JWT token identifier (`jti`) is added to the server revocation list, immediately invalidating subsequent requests.
