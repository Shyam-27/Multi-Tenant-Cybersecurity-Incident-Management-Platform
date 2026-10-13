from datetime import datetime, timezone

from fastapi import HTTPException, status

from app.models.incident import IncidentStatus

# Centralized status transition map
VALID_STATUS_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {IncidentStatus.INVESTIGATING},
    IncidentStatus.INVESTIGATING: {IncidentStatus.CONTAINED, IncidentStatus.RESOLVED},
    IncidentStatus.CONTAINED: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED},
    IncidentStatus.RESOLVED: {IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},
    IncidentStatus.CLOSED: set(),  # Terminal state
}


def validate_status_transition(current_status_str: str, target_status_str: str) -> None:
    try:
        current_status = IncidentStatus(current_status_str)
        target_status = IncidentStatus(target_status_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status value: {target_status_str}",
        )

    # Self-transition is a no-op / valid
    if current_status == target_status:
        return

    allowed_next_states = VALID_STATUS_TRANSITIONS.get(current_status, set())
    if target_status not in allowed_next_states:
        allowed_names = [s.value for s in allowed_next_states]
        detail_msg = (
            f"Invalid status transition from {current_status.value} to {target_status.value}. "
            f"Allowed next states: {allowed_names or 'None (Terminal state)'}"
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail_msg,
        )


def compute_resolved_at(current_status_str: str, new_status_str: str, current_resolved_at: datetime | None) -> datetime | None:
    current_status = IncidentStatus(current_status_str)
    new_status = IncidentStatus(new_status_str)

    if new_status == IncidentStatus.RESOLVED:
        return datetime.now(timezone.utc)
    if current_status == IncidentStatus.RESOLVED and new_status == IncidentStatus.INVESTIGATING:
        return None
    return current_resolved_at
