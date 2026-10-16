from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
import socket
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4
import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import ActorType, AuditOutcome
from app.models.user import User
from app.models.webhook import DeliveryStatus, DestinationType, NotificationDestination, WebhookDelivery
from app.services.audit_service import record_audit_event, sanitize_audit_details

logger = logging.getLogger("sentinelops.webhooks")

# Blocked IP networks for SSRF defense
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_destination_url(url: str, allow_local: bool = False) -> str:
    """
    Validates webhook URL and blocks SSRF attacks against internal network,
    loopback addresses, link-local metadata endpoints, and non-HTTP schemes.
    """
    if not url or not url.strip():
        raise ValueError("Endpoint URL cannot be empty")

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Webhook URL scheme must be http or https")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL must contain a valid hostname")

    # If local webhooks are explicitly allowed (e.g. for testing environments)
    if allow_local:
        return url.strip()

    # Block well-known cloud metadata hostnames
    if hostname.lower() in ("metadata.google.internal", "instance-data", "localhost"):
        raise ValueError(f"Prohibited internal target hostname: '{hostname}'")

    # Resolve hostname to IP to prevent DNS-rebinding and private subnet reachability
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        for item in addr_info:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            for blocked_net in BLOCKED_NETWORKS:
                if ip_obj in blocked_net:
                    raise ValueError(f"Webhook destination resolves to prohibited IP address '{ip_str}'")
    except socket.gaierror as exc:
        raise ValueError(f"Failed to resolve hostname '{hostname}': {exc}") from exc

    return url.strip()


def format_webhook_payload(
    destination_type: str,
    event_type: str,
    raw_payload: dict[str, Any],
    secret_token: str | None,
) -> tuple[dict[str, str], dict[str, Any]]:
    """
    Transforms internal alert into destination-specific format (Splunk, Elastic, Teams, Slack).
    Returns (headers, formatted_body).
    """
    sanitized = sanitize_audit_details(raw_payload)
    headers = {"Content-Type": "application/json"}
    now_iso = datetime.now(timezone.utc).isoformat()

    dtype = destination_type.upper()

    if dtype == DestinationType.SPLUNK_HEC.value:
        if secret_token:
            headers["Authorization"] = f"Splunk {secret_token}"
        body = {
            "time": int(datetime.now(timezone.utc).timestamp()),
            "source": "sentinelops",
            "sourcetype": "_json",
            "event": {
                "event_type": event_type,
                "timestamp": now_iso,
                "data": sanitized,
            },
        }
        return headers, body

    elif dtype == DestinationType.ELASTIC_SIEM.value:
        if secret_token:
            headers["Authorization"] = f"ApiKey {secret_token}"
        body = {
            "@timestamp": now_iso,
            "event": {
                "kind": "alert",
                "category": "security",
                "action": event_type,
            },
            "sentinelops": sanitized,
        }
        return headers, body

    elif dtype == DestinationType.MS_TEAMS.value:
        summary_text = sanitized.get("title") or sanitized.get("action") or event_type
        facts = [{"name": k, "value": str(v)[:100]} for k, v in list(sanitized.items())[:6]]
        body = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "E81123" if "critical" in event_type.lower() else "0078D7",
            "summary": f"SentinelOps Alert: {event_type}",
            "sections": [
                {
                    "activityTitle": f"🛡️ SentinelOps Security Event: {event_type}",
                    "activitySubtitle": now_iso,
                    "text": str(summary_text),
                    "facts": facts,
                }
            ],
        }
        return headers, body

    elif dtype == DestinationType.SLACK.value:
        summary_text = sanitized.get("title") or sanitized.get("action") or event_type
        body = {
            "text": f"🚨 *SentinelOps Alert: {event_type}*",
            "attachments": [
                {
                    "color": "#ef4444" if "critical" in event_type.lower() else "#3b82f6",
                    "title": str(summary_text),
                    "fields": [
                        {"title": k, "value": str(v)[:100], "short": True}
                        for k, v in list(sanitized.items())[:6]
                    ],
                    "footer": "SentinelOps Alerting Engine",
                    "ts": int(datetime.now(timezone.utc).timestamp()),
                }
            ],
        }
        return headers, body

    else:
        # Default generic JSON webhook
        if secret_token:
            headers["Authorization"] = f"Bearer {secret_token}"
        body = {
            "event_type": event_type,
            "timestamp": now_iso,
            "payload": sanitized,
        }
        return headers, body


def deliver_webhook_now(
    destination: NotificationDestination,
    event_type: str,
    payload: dict[str, Any],
    delivery_id: UUID | None = None,
    client: httpx.Client | None = None,
) -> tuple[bool, int | None, str | None]:
    """
    Performs outbound HTTP dispatch to the destination endpoint with strict timeout.
    Returns: (is_success, status_code, error_summary)
    """
    settings = get_settings()
    timeout = float(settings.webhook_timeout_seconds)

    headers, body = format_webhook_payload(
        destination_type=destination.destination_type,
        event_type=event_type,
        raw_payload=payload,
        secret_token=destination.secret_token,
    )

    should_close_client = False
    if client is None:
        client = httpx.Client(timeout=timeout)
        should_close_client = True

    try:
        resp = client.post(destination.endpoint_url, headers=headers, json=body)
        if 200 <= resp.status_code < 300:
            return True, resp.status_code, None
        else:
            return False, resp.status_code, f"HTTP status {resp.status_code}: {resp.text[:200]}"
    except httpx.TimeoutException:
        return False, None, "Connection timed out"
    except Exception as exc:
        return False, None, str(exc)[:300]
    finally:
        if should_close_client:
            client.close()


def dispatch_event_to_destinations(
    db: Session,
    tenant_id: UUID,
    event_type: str,
    payload: dict[str, Any],
    actor_user: User | None = None,
    client: httpx.Client | None = None,
) -> list[WebhookDelivery]:
    """
    Asynchronously or synchronously dispatches events to all active subscribed destinations.
    Enforces deduplication / idempotency and records outcomes.
    """
    settings = get_settings()

    # Find matching active destinations for this tenant
    destinations = db.scalars(
        select(NotificationDestination)
        .where(
            NotificationDestination.tenant_id == tenant_id,
            NotificationDestination.is_enabled == True,
        )
    ).all()

    deliveries: list[WebhookDelivery] = []
    now = datetime.now(timezone.utc)

    for dest in destinations:
        # Check event subscription match: exact match, wildcards, or empty list (all events)
        if dest.event_types and event_type not in dest.event_types and "*" not in dest.event_types:
            continue

        idempotency_key = f"{tenant_id}_{dest.id}_{event_type}_{payload.get('id', '')}_{now.strftime('%Y%m%d%H%M')}"

        # Deduplication check
        existing = db.scalar(
            select(WebhookDelivery).where(WebhookDelivery.idempotency_key == idempotency_key)
        )
        if existing and existing.status == DeliveryStatus.SUCCESS.value:
            continue

        delivery = WebhookDelivery(
            tenant_id=tenant_id,
            destination_id=dest.id,
            event_type=event_type,
            payload=sanitize_audit_details(payload),
            status=DeliveryStatus.PENDING.value,
            attempt_count=1,
            max_attempts=settings.webhook_max_retries,
            last_attempt_at=now,
            idempotency_key=idempotency_key,
        )
        db.add(delivery)
        db.flush()

        success, code, err = deliver_webhook_now(dest, event_type, payload, delivery.id, client=client)
        delivery.response_status_code = code

        if success:
            delivery.status = DeliveryStatus.SUCCESS.value
            delivery.error_summary = None
        else:
            delivery.error_summary = err
            if delivery.attempt_count < delivery.max_attempts:
                delivery.status = DeliveryStatus.RETRYING.value
                delivery.next_retry_at = now + timedelta(seconds=15 * delivery.attempt_count)
            else:
                delivery.status = DeliveryStatus.FAILED.value

        deliveries.append(delivery)

    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("Failed to commit webhook deliveries: %s", exc)

    return deliveries


def send_test_webhook(
    db: Session,
    destination: NotificationDestination,
    actor_user: User | None = None,
    client: httpx.Client | None = None,
) -> tuple[bool, int | None, str | None]:
    """Sends an explicit synthetic test event to a destination."""
    test_event_type = "test.ping"
    test_payload = {
        "message": "SentinelOps SIEM/Webhook test ping",
        "destination_name": destination.name,
        "destination_type": destination.destination_type,
        "tenant_id": str(destination.tenant_id),
        "dispatched_by": actor_user.email if actor_user else "system",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    success, code, err = deliver_webhook_now(destination, test_event_type, test_payload, client=client)

    # Record delivery log
    delivery = WebhookDelivery(
        tenant_id=destination.tenant_id,
        destination_id=destination.id,
        event_type=test_event_type,
        payload=test_payload,
        status=DeliveryStatus.SUCCESS.value if success else DeliveryStatus.FAILED.value,
        attempt_count=1,
        max_attempts=1,
        last_attempt_at=datetime.now(timezone.utc),
        response_status_code=code,
        error_summary=err,
    )
    db.add(delivery)

    # Record audit event without webhook recursion
    record_audit_event(
        db=db,
        action="WEBHOOK_TEST_DISPATCHED",
        resource_type="webhook_destination",
        resource_id=str(destination.id),
        outcome=AuditOutcome.SUCCESS if success else AuditOutcome.FAILURE,
        actor_user=actor_user,
        actor_type=ActorType.USER if actor_user else ActorType.SYSTEM,
        tenant_id=destination.tenant_id,
        details={
            "destination_name": destination.name,
            "status_code": code,
            "success": success,
            "error": err,
        },
    )
    db.commit()

    return success, code, err
