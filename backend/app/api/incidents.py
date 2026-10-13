from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.dependencies.auth import get_current_user, require_roles
from app.models.incident import (
    Incident,
    IncidentCategory,
    IncidentNote,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.user import User, UserRole
from app.schemas.incident import (
    CreateIncidentRequest,
    CreateNoteRequest,
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentMetricsResponse,
    IncidentNoteResponse,
    UpdateIncidentRequest,
)
from app.services.incident_service import compute_resolved_at, validate_status_transition

router = APIRouter(prefix="/incidents", tags=["incidents"])

SORT_FIELD_MAP = {
    "created_at": Incident.created_at,
    "updated_at": Incident.updated_at,
    "severity": Incident.severity,
    "status": Incident.status,
    "title": Incident.title,
}


def _format_incident_response(incident: Incident) -> IncidentDetailResponse:
    notes_responses = [
        IncidentNoteResponse(
            id=n.id,
            tenant_id=n.tenant_id,
            incident_id=n.incident_id,
            author_id=n.author_id,
            author_name=n.author.name if n.author else None,
            content=n.content,
            created_at=n.created_at,
        )
        for n in incident.notes
    ]

    return IncidentDetailResponse(
        id=incident.id,
        tenant_id=incident.tenant_id,
        title=incident.title,
        description=incident.description,
        category=incident.category,
        severity=incident.severity,
        status=incident.status,
        assigned_to_id=incident.assigned_to_id,
        assigned_to_name=incident.assigned_to.name if incident.assigned_to else None,
        created_by_id=incident.created_by_id,
        created_by_name=incident.created_by.name if incident.created_by else None,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        notes=notes_responses,
    )


@router.get("/metrics", response_model=IncidentMetricsResponse)
def get_incident_metrics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentMetricsResponse:
    base_filter = []
    if current_user.role != UserRole.SUPER_ADMIN.value:
        base_filter.append(Incident.tenant_id == current_user.tenant_id)

    total = db.scalar(select(func.count(Incident.id)).where(*base_filter)) or 0
    open_count = db.scalar(
        select(func.count(Incident.id)).where(*base_filter, Incident.status == IncidentStatus.OPEN.value)
    ) or 0
    investigating_count = db.scalar(
        select(func.count(Incident.id)).where(*base_filter, Incident.status == IncidentStatus.INVESTIGATING.value)
    ) or 0
    contained_count = db.scalar(
        select(func.count(Incident.id)).where(*base_filter, Incident.status == IncidentStatus.CONTAINED.value)
    ) or 0
    resolved_count = db.scalar(
        select(func.count(Incident.id)).where(*base_filter, Incident.status == IncidentStatus.RESOLVED.value)
    ) or 0
    closed_count = db.scalar(
        select(func.count(Incident.id)).where(*base_filter, Incident.status == IncidentStatus.CLOSED.value)
    ) or 0
    crit_high_count = db.scalar(
        select(func.count(Incident.id)).where(
            *base_filter,
            Incident.severity.in_([IncidentSeverity.CRITICAL.value, IncidentSeverity.HIGH.value]),
        )
    ) or 0

    return IncidentMetricsResponse(
        total=total,
        open=open_count,
        investigating=investigating_count,
        contained=contained_count,
        resolved=resolved_count,
        closed=closed_count,
        critical_and_high=crit_high_count,
    )


@router.post("", response_model=IncidentDetailResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    data: CreateIncidentRequest,
    current_user: User = Depends(
        require_roles(UserRole.TENANT_ADMIN, UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN)
    ),
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    if current_user.tenant_id is None and current_user.role == UserRole.SUPER_ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Platform super admin must specify or belong to a tenant context to create an incident",
        )

    target_tenant_id = current_user.tenant_id

    # Validate analyst assignment if provided
    assigned_user = None
    if data.assigned_to_id is not None:
        assigned_user = db.scalar(
            select(User).where(
                User.id == data.assigned_to_id,
                User.tenant_id == target_tenant_id,
                User.is_active == True,  # noqa: E712
            )
        )
        if assigned_user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assigned analyst must be an active user in the same organization",
            )
        if assigned_user.role not in [UserRole.SECURITY_ANALYST.value, UserRole.TENANT_ADMIN.value]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incidents may only be assigned to a SECURITY_ANALYST or TENANT_ADMIN",
            )

    incident = Incident(
        tenant_id=target_tenant_id,
        title=data.title.strip(),
        description=data.description.strip(),
        category=data.category.value,
        severity=data.severity.value,
        status=IncidentStatus.OPEN.value,
        assigned_to_id=data.assigned_to_id,
        created_by_id=current_user.id,
    )
    db.add(incident)
    db.commit()

    # Re-fetch with loaded relations
    loaded_incident = db.scalar(
        select(Incident)
        .options(
            selectinload(Incident.assigned_to),
            selectinload(Incident.created_by),
            selectinload(Incident.notes).selectinload(IncidentNote.author),
        )
        .where(Incident.id == incident.id)
    )
    return _format_incident_response(loaded_incident)


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity_filter: IncidentSeverity | None = Query(default=None, alias="severity"),
    category_filter: str | None = Query(default=None, alias="category"),
    assigned_to_id: UUID | None = None,
    search: str | None = None,
    sort_by: str = Query(default="created_at"),
    sort_order: str = Query(default="desc"),
    tenant_id: UUID | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentListResponse:
    query = select(Incident).options(
        selectinload(Incident.assigned_to),
        selectinload(Incident.created_by),
        selectinload(Incident.notes).selectinload(IncidentNote.author),
    )

    # Scoping
    if current_user.role == UserRole.SUPER_ADMIN.value:
        if tenant_id is not None:
            query = query.where(Incident.tenant_id == tenant_id)
    else:
        query = query.where(Incident.tenant_id == current_user.tenant_id)

    # Filters
    if status_filter is not None:
        query = query.where(Incident.status == status_filter.value)
    if severity_filter is not None:
        query = query.where(Incident.severity == severity_filter.value)
    if category_filter is not None:
        query = query.where(Incident.category == category_filter.strip())
    if assigned_to_id is not None:
        query = query.where(Incident.assigned_to_id == assigned_to_id)
    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.where(
            or_(
                Incident.title.ilike(search_pattern),
                Incident.description.ilike(search_pattern),
            )
        )

    # Total count query
    count_query = select(func.count()).select_from(query.subquery())
    total_count = db.scalar(count_query) or 0

    # Sorting
    sort_column = SORT_FIELD_MAP.get(sort_by, Incident.created_at)
    if sort_order.lower() == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    # Pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    incidents = db.scalars(query).all()
    total_pages = ceil(total_count / page_size) if total_count > 0 else 1

    return IncidentListResponse(
        items=[_format_incident_response(i) for i in incidents],
        total=total_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_by_id(
    incident_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    incident = db.scalar(
        select(Incident)
        .options(
            selectinload(Incident.assigned_to),
            selectinload(Incident.created_by),
            selectinload(Incident.notes).selectinload(IncidentNote.author),
        )
        .where(Incident.id == incident_id)
    )

    # Return 404 for missing or cross-tenant records (prevent IDOR)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and incident.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    return _format_incident_response(incident)


@router.patch("/{incident_id}", response_model=IncidentDetailResponse)
def update_incident(
    incident_id: UUID,
    data: UpdateIncidentRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))

    # Anti-IDOR check first: return 404 for missing or cross-tenant records
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and incident.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    # Role permission check: SECURITY_VIEWER is forbidden from modifying incidents
    if current_user.role == UserRole.SECURITY_VIEWER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security viewers are not permitted to modify incidents",
        )

    # Validate analyst assignment if provided
    if data.assigned_to_id is not None and data.assigned_to_id != incident.assigned_to_id:
        assigned_user = db.scalar(
            select(User).where(
                User.id == data.assigned_to_id,
                User.tenant_id == incident.tenant_id,
                User.is_active == True,  # noqa: E712
            )
        )
        if assigned_user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Assigned analyst must be an active user in the same organization",
            )
        if assigned_user.role not in [UserRole.SECURITY_ANALYST.value, UserRole.TENANT_ADMIN.value]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incidents may only be assigned to a SECURITY_ANALYST or TENANT_ADMIN",
            )
        incident.assigned_to_id = data.assigned_to_id

    # Validate status transition if status is being changed
    if data.status is not None and data.status.value != incident.status:
        validate_status_transition(incident.status, data.status.value)
        incident.resolved_at = compute_resolved_at(incident.status, data.status.value, incident.resolved_at)
        incident.status = data.status.value

    if data.title is not None:
        incident.title = data.title.strip()
    if data.description is not None:
        incident.description = data.description.strip()
    if data.category is not None:
        incident.category = data.category.value
    if data.severity is not None:
        incident.severity = data.severity.value

    db.commit()

    loaded_incident = db.scalar(
        select(Incident)
        .options(
            selectinload(Incident.assigned_to),
            selectinload(Incident.created_by),
            selectinload(Incident.notes).selectinload(IncidentNote.author),
        )
        .where(Incident.id == incident.id)
    )
    return _format_incident_response(loaded_incident)


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse, status_code=status.HTTP_201_CREATED)
def add_investigation_note(
    incident_id: UUID,
    data: CreateNoteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> IncidentNoteResponse:
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))

    # Anti-IDOR check first: return 404 for missing or cross-tenant records
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and incident.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    # Role permission check: SECURITY_VIEWER is forbidden from creating notes
    if current_user.role == UserRole.SECURITY_VIEWER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security viewers are not permitted to add investigation notes",
        )

    note_text = data.content.strip()
    if not note_text:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Note content cannot be empty")

    note = IncidentNote(
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        author_id=current_user.id,
        content=note_text,
    )
    db.add(note)
    db.commit()
    db.refresh(note)

    return IncidentNoteResponse(
        id=note.id,
        tenant_id=note.tenant_id,
        incident_id=note.incident_id,
        author_id=note.author_id,
        author_name=current_user.name,
        content=note.content,
        created_at=note.created_at,
    )
