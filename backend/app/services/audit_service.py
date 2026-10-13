from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any
from uuid import UUID, uuid4

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import ActorType, AuditEvent, AuditOutcome
from app.models.user import User

logger = logging.getLogger("sentinelops.audit")

# Sensitive keys that must be strictly redacted from any audit details
SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "authorization",
    "cookie",
    "file_content",
    "raw_body",
}


def sanitize_audit_details(data: dict[str, Any] | None) -> dict[str, Any]:
    """
    Sanitize audit event details to ensure no credentials, tokens, or
    unbounded payloads enter the persistent audit log.
    """
    if not data:
        return {}

    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        key_lower = key.lower()
        if any(sens in key_lower for sens in SENSITIVE_KEYS):
            sanitized[key] = "[REDACTED]"
            continue

        if isinstance(value, dict):
            sanitized[key] = sanitize_audit_details(value)
        elif isinstance(value, (list, tuple)):
            sanitized[key] = [
                sanitize_audit_details(item) if isinstance(item, dict) else str(item)[:200]
                for item in value[:20]  # limit array length
            ]
        elif isinstance(value, str):
            sanitized[key] = value[:500]  # truncate long strings
        elif isinstance(value, (int, float, bool)) or value is None:
            sanitized[key] = value
        else:
            sanitized[key] = str(value)[:200]

    return sanitized


def canonical_serialize_event(
    id_str: str,
    tenant_id_str: str,
    actor_user_id_str: str,
    actor_type: str,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str,
    occurred_at_iso: str,
    previous_hash: str,
    details: dict[str, Any],
) -> str:
    """
    Deterministic JSON serialization for cryptographic hash chain integrity.
    """
    payload = {
        "id": id_str,
        "tenant_id": tenant_id_str,
        "actor_user_id": actor_user_id_str,
        "actor_type": actor_type,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "occurred_at": occurred_at_iso,
        "previous_hash": previous_hash,
        "details": details,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_event_hash(
    id_str: str,
    tenant_id_str: str,
    actor_user_id_str: str,
    actor_type: str,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str,
    occurred_at_iso: str,
    previous_hash: str,
    details: dict[str, Any],
) -> str:
    canonical = canonical_serialize_event(
        id_str=id_str,
        tenant_id_str=tenant_id_str,
        actor_user_id_str=actor_user_id_str,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        occurred_at_iso=occurred_at_iso,
        previous_hash=previous_hash,
        details=details,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_request_meta(request: Request | None) -> tuple[str | None, str | None, str | None]:
    """Extract request_id, client_ip, and user_agent safely."""
    if not request:
        return None, None, None

    request_id = request.headers.get("x-request-id")
    # Respect proxy client IP safely or fallback to client.host
    client_ip = request.headers.get("x-forwarded-for")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()[:45]
    elif request.client:
        client_ip = request.client.host[:45]
    else:
        client_ip = None

    user_agent = request.headers.get("user-agent", "")[:512] or None
    return request_id, client_ip, user_agent


def record_audit_event(
    db: Session,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    actor_user: User | None = None,
    actor_type: ActorType = ActorType.USER,
    tenant_id: UUID | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> AuditEvent:
    """
    Centralized append-only audit event recording service.
    Computes cryptographic SHA-256 hash chains per tenant to detect tampering.
    """
    # Derive actor and tenant context safely
    actor_user_id = actor_user.id if actor_user else None
    if actor_user and actor_type == ActorType.USER and not tenant_id:
        tenant_id = actor_user.tenant_id

    req_id, ip, ua = extract_request_meta(request)
    effective_req_id = request_id or req_id
    effective_ip = source_ip or ip
    effective_ua = user_agent or ua

    sanitized_details = sanitize_audit_details(details)
    event_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    # 1. Fetch previous event hash for this tenant to maintain integrity chain
    query = (
        select(AuditEvent.event_hash)
        .where(AuditEvent.tenant_id == tenant_id)
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .limit(1)
    )
    last_hash = db.scalar(query)
    prev_hash_str = last_hash or "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000"

    # 2. Compute canonical event hash
    computed_hash = compute_event_hash(
        id_str=str(event_id),
        tenant_id_str=str(tenant_id) if tenant_id else "",
        actor_user_id_str=str(actor_user_id) if actor_user_id else "",
        actor_type=actor_type.value,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id or "",
        outcome=outcome.value,
        occurred_at_iso=now_utc.isoformat(),
        previous_hash=prev_hash_str,
        details=sanitized_details,
    )

    event = AuditEvent(
        id=event_id,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type=actor_type.value,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome.value,
        occurred_at=now_utc,
        request_id=effective_req_id,
        source_ip=effective_ip,
        user_agent=effective_ua,
        details=sanitized_details,
        previous_hash=prev_hash_str,
        event_hash=computed_hash,
    )

    db.add(event)
    return event


def verify_tenant_audit_chain(db: Session, tenant_id: UUID | None) -> tuple[bool, int, UUID | None, str]:
    """
    Verifies the cryptographic hash chain for a tenant's audit trail.
    Returns: (is_valid, verified_count, broken_event_id, explanation)
    """
    events = (
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.occurred_at.asc(), AuditEvent.id.asc())
        )
        .all()
    )

    if not events:
        return True, 0, None, "No audit events found for verification"

    expected_prev = "GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000"
    for idx, ev in enumerate(events):
        # 1. Check previous_hash link
        if ev.previous_hash != expected_prev:
            return (
                False,
                idx,
                ev.id,
                f"Broken previous hash chain link at event {ev.id}: expected {expected_prev}, found {ev.previous_hash}",
            )

        # 2. Re-compute event hash
        occurred_iso = ev.occurred_at.isoformat() if ev.occurred_at.tzinfo else ev.occurred_at.replace(tzinfo=timezone.utc).isoformat()
        recomputed = compute_event_hash(
            id_str=str(ev.id),
            tenant_id_str=str(ev.tenant_id) if ev.tenant_id else "",
            actor_user_id_str=str(ev.actor_user_id) if ev.actor_user_id else "",
            actor_type=ev.actor_type,
            action=ev.action,
            resource_type=ev.resource_type,
            resource_id=ev.resource_id or "",
            outcome=ev.outcome,
            occurred_at_iso=occurred_iso,
            previous_hash=ev.previous_hash or "",
            details=ev.details,
        )

        if ev.event_hash != recomputed:
            return (
                False,
                idx,
                ev.id,
                f"Hash mismatch at event {ev.id}: recorded {ev.event_hash}, computed {recomputed}. Tampering detected.",
            )

        expected_prev = ev.event_hash

    return True, len(events), None, f"All {len(events)} audit events verified cryptographically."
