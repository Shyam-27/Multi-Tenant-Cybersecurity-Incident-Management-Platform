from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.dependencies.auth import get_current_user, require_roles
from app.models.audit import ActorType, AuditOutcome
from app.models.playbook import PlaybookApproval, PlaybookExecution, ResponsePlaybook
from app.models.user import User, UserRole
from app.schemas.playbook import (
    ApprovalDecisionRequest,
    CreatePlaybookRequest,
    ExecutionListResponse,
    ExecutionResponse,
    PlaybookResponse,
    TriggerExecutionRequest,
    UpdatePlaybookRequest,
)
from app.services.audit_service import record_audit_event
from app.services.playbook_service import decide_playbook_approval, trigger_playbook_execution

router = APIRouter(prefix="/playbooks", tags=["response-playbooks"])


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
def create_playbook(
    payload: CreatePlaybookRequest,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> ResponsePlaybook:
    # Validate actions
    if not payload.actions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Playbook must contain at least one action definition",
        )

    playbook = ResponsePlaybook(
        tenant_id=current_user.tenant_id,
        name=payload.name.strip(),
        description=payload.description.strip(),
        trigger_event=payload.trigger_event.strip(),
        actions=payload.actions,
        is_enabled=payload.is_enabled,
        is_dry_run=payload.is_dry_run,
        requires_approval=payload.requires_approval,
        created_by_id=current_user.id,
    )
    db.add(playbook)
    db.flush()

    record_audit_event(
        db=db,
        action="PLAYBOOK_CREATED",
        resource_type="playbook",
        resource_id=str(playbook.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={
            "name": playbook.name,
            "actions_count": len(playbook.actions),
            "is_dry_run": playbook.is_dry_run,
        },
    )
    db.commit()
    db.refresh(playbook)
    return playbook


@router.get("", response_model=list[PlaybookResponse])
def list_playbooks(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ResponsePlaybook]:
    query = select(ResponsePlaybook)
    if current_user.role != UserRole.SUPER_ADMIN.value:
        query = query.where(ResponsePlaybook.tenant_id == current_user.tenant_id)

    return db.scalars(query.order_by(ResponsePlaybook.created_at.desc())).all()


@router.get("/{id}", response_model=PlaybookResponse)
def get_playbook(
    id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ResponsePlaybook:
    playbook = db.scalar(select(ResponsePlaybook).where(ResponsePlaybook.id == id))
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and playbook.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    return playbook


@router.patch("/{id}", response_model=PlaybookResponse)
def update_playbook(
    id: UUID,
    payload: UpdatePlaybookRequest,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> ResponsePlaybook:
    playbook = db.scalar(select(ResponsePlaybook).where(ResponsePlaybook.id == id))
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and playbook.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    if payload.name is not None:
        playbook.name = payload.name.strip()
    if payload.description is not None:
        playbook.description = payload.description.strip()
    if payload.actions is not None:
        if not payload.actions:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Actions list cannot be empty")
        playbook.actions = payload.actions
    if payload.is_enabled is not None:
        playbook.is_enabled = payload.is_enabled
    if payload.is_dry_run is not None:
        playbook.is_dry_run = payload.is_dry_run
    if payload.requires_approval is not None:
        playbook.requires_approval = payload.requires_approval

    record_audit_event(
        db=db,
        action="PLAYBOOK_UPDATED",
        resource_type="playbook",
        resource_id=str(playbook.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=playbook.tenant_id,
        details={"name": playbook.name, "is_dry_run": playbook.is_dry_run},
    )
    db.commit()
    db.refresh(playbook)
    return playbook


@router.post("/{id}/execute", response_model=ExecutionResponse)
def execute_playbook(
    id: UUID,
    payload: TriggerExecutionRequest | None = None,
    x_mfa_code: str | None = Header(default=None, alias="X-MFA-Code"),
    x_step_up_token: str | None = Header(default=None, alias="X-Step-Up-Token"),
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> PlaybookExecution:
    playbook = db.scalar(select(ResponsePlaybook).where(ResponsePlaybook.id == id))
    if not playbook:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and playbook.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    if not playbook.is_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot execute a disabled playbook")

    params = payload.parameters if payload else {}
    inc_id = payload.incident_id if payload else None
    override_dry_run = payload.override_dry_run if payload else None
    mfa_code = (payload.mfa_code if payload and payload.mfa_code else None) or x_mfa_code
    step_up_token = (payload.step_up_token if payload and payload.step_up_token else None) or x_step_up_token

    # Analysts are restricted to dry-run only unless approved
    if current_user.role == UserRole.SECURITY_ANALYST.value and override_dry_run is False:
        override_dry_run = None  # Force playbook default or approval requirements

    try:
        execution = trigger_playbook_execution(
            db=db,
            playbook=playbook,
            actor_user=current_user,
            parameters=params,
            incident_id=inc_id,
            override_dry_run=override_dry_run,
            step_up_token=step_up_token,
            mfa_code=mfa_code,
        )
        return execution
    except ValueError as exc:
        if "not found" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        if "step-up" in str(exc).lower() or "mfa" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/executions/list", response_model=ExecutionListResponse)
def list_executions(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ExecutionListResponse:
    query = select(PlaybookExecution).options(joinedload(PlaybookExecution.approval))
    if current_user.role != UserRole.SUPER_ADMIN.value:
        query = query.where(PlaybookExecution.tenant_id == current_user.tenant_id)

    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    pages = max(1, ceil(total / page_size))
    offset = (page - 1) * page_size

    items = db.scalars(
        query.order_by(PlaybookExecution.created_at.desc()).offset(offset).limit(page_size)
    ).unique().all()

    return ExecutionListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/executions/{id}", response_model=ExecutionResponse)
def get_execution(
    id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookExecution:
    execution = db.scalar(
        select(PlaybookExecution)
        .options(joinedload(PlaybookExecution.approval))
        .where(PlaybookExecution.id == id)
    )
    if not execution:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and execution.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")

    return execution


@router.post("/executions/{id}/approve", response_model=ExecutionResponse)
def approve_execution(
    id: UUID,
    payload: ApprovalDecisionRequest | None = None,
    x_mfa_code: str | None = Header(default=None, alias="X-MFA-Code"),
    x_step_up_token: str | None = Header(default=None, alias="X-Step-Up-Token"),
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> PlaybookExecution:
    notes = payload.notes if payload else None
    mfa_code = (payload.mfa_code if payload and payload.mfa_code else None) or x_mfa_code
    step_up_token = (payload.step_up_token if payload and payload.step_up_token else None) or x_step_up_token
    try:
        updated = decide_playbook_approval(
            db=db,
            execution_id=id,
            approver=current_user,
            approved=True,
            notes=notes,
            step_up_token=step_up_token,
            mfa_code=mfa_code,
        )
        return updated
    except ValueError as exc:
        if "not found" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        if "step-up" in str(exc).lower() or "mfa" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/executions/{id}/reject", response_model=ExecutionResponse)
def reject_execution(
    id: UUID,
    payload: ApprovalDecisionRequest | None = None,
    current_user: User = Depends(require_roles(UserRole.TENANT_ADMIN, UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
) -> PlaybookExecution:
    notes = payload.notes if payload else None
    try:
        updated = decide_playbook_approval(
            db=db,
            execution_id=id,
            approver=current_user,
            approved=False,
            notes=notes,
        )
        return updated
    except ValueError as exc:
        if "not found" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
