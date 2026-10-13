import mimetypes
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.dependencies.auth import get_current_user
from app.models.audit import ActorType, AuditOutcome
from app.models.evidence import Evidence
from app.models.incident import Incident
from app.models.user import User, UserRole
from app.schemas.evidence import EvidenceResponse
from app.services.audit_service import record_audit_event
from app.services.evidence_service import get_safe_evidence_path, save_evidence_file
from fastapi import Request

router = APIRouter(prefix="/incidents", tags=["evidence"])
settings = get_settings()


def _format_evidence_response(evidence: Evidence) -> EvidenceResponse:
    return EvidenceResponse(
        id=evidence.id,
        tenant_id=evidence.tenant_id,
        incident_id=evidence.incident_id,
        uploaded_by_id=evidence.uploaded_by_id,
        uploaded_by_name=evidence.uploaded_by.name if evidence.uploaded_by else None,
        filename=evidence.filename,
        file_size_bytes=evidence.file_size_bytes,
        sha256_hash=evidence.sha256_hash,
        mime_type=evidence.mime_type,
        description=evidence.description,
        created_at=evidence.created_at,
    )


@router.post("/{incident_id}/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def upload_incident_evidence(
    incident_id: UUID,
    request: Request,
    file: UploadFile = File(...),
    description: str = Form(default=""),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EvidenceResponse:
    # 1. Fetch incident and verify tenant access (Anti-IDOR)
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and incident.tenant_id != current_user.tenant_id:
        record_audit_event(
            db=db,
            action="CROSS_TENANT_ACCESS_DENIED",
            resource_type="incident",
            resource_id=str(incident_id),
            outcome=AuditOutcome.DENIED,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=current_user.tenant_id,
            details={"attempted_incident_id": str(incident_id)},
            request=request,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    # 2. RBAC check: SECURITY_VIEWER is not allowed to upload evidence
    if current_user.role == UserRole.SECURITY_VIEWER.value:
        record_audit_event(
            db=db,
            action="EVIDENCE_UPLOAD_DENIED",
            resource_type="incident",
            resource_id=str(incident.id),
            outcome=AuditOutcome.DENIED,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=incident.tenant_id,
            details={"reason": "insufficient_role_security_viewer"},
            request=request,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security viewers are not permitted to upload evidence",
        )

    # 3. Create preliminary evidence DB record to get unique UUID
    import uuid
    evidence_id = uuid.uuid4()

    # 4. Stream and validate file safely
    try:
        stored_path, clean_name, file_size, sha256_hash, detected_mime = await save_evidence_file(
            upload_file=file,
            base_dir=settings.upload_dir,
            tenant_id=incident.tenant_id,
            incident_id=incident.id,
            evidence_id=evidence_id,
            max_size=settings.max_upload_size,
        )
    except HTTPException as http_exc:
        record_audit_event(
            db=db,
            action="EVIDENCE_VALIDATION_FAILED",
            resource_type="evidence",
            outcome=AuditOutcome.FAILURE,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=incident.tenant_id,
            details={"filename": file.filename, "error": http_exc.detail},
            request=request,
        )
        db.commit()
        raise
    except Exception as exc:
        record_audit_event(
            db=db,
            action="EVIDENCE_UPLOAD_ERROR",
            resource_type="evidence",
            outcome=AuditOutcome.FAILURE,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=incident.tenant_id,
            details={"filename": file.filename, "error": str(exc)},
            request=request,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process and store evidence file: {str(exc)}",
        )

    # 5. Persist evidence record in DB
    evidence = Evidence(
        id=evidence_id,
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        uploaded_by_id=current_user.id,
        filename=clean_name,
        file_path=stored_path,
        file_size_bytes=file_size,
        sha256_hash=sha256_hash,
        mime_type=detected_mime,
        description=description.strip()[:1000],
    )
    db.add(evidence)
    db.flush()

    record_audit_event(
        db=db,
        action="EVIDENCE_UPLOADED",
        resource_type="evidence",
        resource_id=str(evidence.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=evidence.tenant_id,
        details={
            "incident_id": str(incident.id),
            "filename": evidence.filename,
            "file_size_bytes": evidence.file_size_bytes,
            "sha256_hash": evidence.sha256_hash,
            "mime_type": evidence.mime_type,
        },
        request=request,
    )

    db.commit()
    db.refresh(evidence)

    # Re-fetch with uploaded_by relationship loaded
    evidence = db.scalar(
        select(Evidence)
        .options(selectinload(Evidence.uploaded_by))
        .where(Evidence.id == evidence.id)
    )

    return _format_evidence_response(evidence)


@router.get("/{incident_id}/evidence", response_model=list[EvidenceResponse])
def list_incident_evidence(
    incident_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[EvidenceResponse]:
    # 1. Fetch incident and verify tenant access (Anti-IDOR)
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and incident.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    # 2. Fetch evidence list
    query = (
        select(Evidence)
        .options(selectinload(Evidence.uploaded_by))
        .where(Evidence.incident_id == incident_id)
        .order_by(Evidence.created_at.asc())
    )
    if current_user.role != UserRole.SUPER_ADMIN.value:
        query = query.where(Evidence.tenant_id == current_user.tenant_id)

    items = db.scalars(query).all()
    return [_format_evidence_response(e) for e in items]


@router.get("/{incident_id}/evidence/{evidence_id}/download")
def download_incident_evidence(
    incident_id: UUID,
    evidence_id: UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1. Fetch incident and verify tenant access (Anti-IDOR)
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and incident.tenant_id != current_user.tenant_id:
        record_audit_event(
            db=db,
            action="CROSS_TENANT_ACCESS_DENIED",
            resource_type="incident",
            resource_id=str(incident_id),
            outcome=AuditOutcome.DENIED,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=current_user.tenant_id,
            details={"attempted_incident_id": str(incident_id)},
            request=request,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    # 2. Fetch evidence record
    evidence = db.scalar(
        select(Evidence).where(
            Evidence.id == evidence_id,
            Evidence.incident_id == incident_id,
        )
    )
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    if current_user.role != UserRole.SUPER_ADMIN.value and evidence.tenant_id != current_user.tenant_id:
        record_audit_event(
            db=db,
            action="CROSS_TENANT_ACCESS_DENIED",
            resource_type="evidence",
            resource_id=str(evidence_id),
            outcome=AuditOutcome.DENIED,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=current_user.tenant_id,
            details={"attempted_evidence_id": str(evidence_id)},
            request=request,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    # 3. Resolve safe path
    safe_path = get_safe_evidence_path(settings.upload_dir, evidence.tenant_id, evidence.file_path)

    record_audit_event(
        db=db,
        action="EVIDENCE_DOWNLOADED",
        resource_type="evidence",
        resource_id=str(evidence.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=evidence.tenant_id,
        details={"incident_id": str(incident.id), "filename": evidence.filename},
        request=request,
    )
    db.commit()

    # 4. Return streaming response with security headers
    response = FileResponse(
        path=safe_path,
        media_type="application/octet-stream",
        filename=evidence.filename,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Disposition"] = f'attachment; filename="{evidence.filename}"'
    return response
