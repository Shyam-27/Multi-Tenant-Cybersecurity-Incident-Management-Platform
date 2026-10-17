from datetime import datetime, timezone
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_step_up_token,
    decode_mfa_challenge_token,
    revoke_token,
    verify_password,
)
from app.dependencies.auth import get_current_user
from app.models.audit import ActorType, AuditOutcome
from app.models.user import User, UserRecoveryCode
from app.schemas.auth import TokenResponse
from app.schemas.mfa import (
    MFAConfirmEnrollRequest,
    MFADisableRequest,
    MFAEnrollResponse,
    MFARecoveryCodesResponse,
    MFARegenerateRecoveryCodesRequest,
    MFAStatusResponse,
    MFAStepUpRequest,
    MFAStepUpResponse,
    MFAVerifyLoginRequest,
)
from app.services.audit_service import record_audit_event
from app.services.mfa_service import (
    check_mfa_lockout,
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_provisioning_uri,
    generate_qr_code_data_uri,
    generate_qr_code_svg,
    generate_recovery_codes,
    generate_totp_secret,
    get_mfa_fernet,
    hash_recovery_code,
    record_mfa_failure,
    record_mfa_success,
    verify_and_consume_recovery_code,
    verify_totp_code,
)

logger = logging.getLogger("sentinelops.api.mfa")
router = APIRouter(prefix="/auth/mfa", tags=["multi-factor-authentication"])


@router.post("/enroll", response_model=MFAEnrollResponse)
def initiate_mfa_enrollment(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MFAEnrollResponse:
    """
    Initiates TOTP MFA enrollment by generating a cryptographically random secret,
    a standards-compatible provisioning URI, a safe QR code, and backup recovery codes.
    MFA is not activated until confirmed with a valid TOTP code.
    """
    try:
        get_mfa_fernet()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled on this account. Disable it first to re-enroll.",
        )

    # Generate fresh TOTP secret and encrypt at rest
    secret = generate_totp_secret()
    current_user.totp_secret_encrypted = encrypt_totp_secret(secret)

    # Generate provisioning URI & QR Code
    uri = generate_provisioning_uri(secret, current_user.email)
    qr_svg = generate_qr_code_svg(uri)

    # Generate 10 single-use recovery codes
    plain_codes = generate_recovery_codes(10)

    # Remove any unconfirmed previous codes for this user
    db.execute(delete(UserRecoveryCode).where(UserRecoveryCode.user_id == current_user.id))

    for code in plain_codes:
        rec = UserRecoveryCode(
            user_id=current_user.id,
            code_hash=hash_recovery_code(code),
            is_used=False,
        )
        db.add(rec)

    record_audit_event(
        db=db,
        action="MFA_ENROLL_INITIATED",
        resource_type="user",
        resource_id=str(current_user.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={"email": current_user.email},
        request=request,
    )

    db.commit()

    return MFAEnrollResponse(
        secret=secret,
        provisioning_uri=uri,
        qr_code=generate_qr_code_data_uri(qr_svg),
        qr_code_svg=qr_svg,
        recovery_codes=plain_codes,
    )


@router.post("/confirm-enroll")
def confirm_mfa_enrollment(
    data: MFAConfirmEnrollRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """
    Confirms and activates TOTP MFA by verifying a valid current code from the authenticator app.
    Enforces rate limits and anti-replay protection.
    """
    if not current_user.totp_secret_encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending MFA enrollment found. Call /enroll first.",
        )

    check_mfa_lockout(current_user)

    try:
        secret = decrypt_totp_secret(current_user.totp_secret_encrypted)
    except Exception as exc:
        logger.error("Failed to decrypt candidate TOTP secret: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt candidate TOTP secret.",
        ) from exc

    is_valid, step = verify_totp_code(secret, data.totp_code, current_user.last_totp_timestep)

    if not is_valid:
        record_mfa_failure(db, current_user)
        record_audit_event(
            db=db,
            action="MFA_ENROLL_FAILED",
            resource_type="user",
            resource_id=str(current_user.id),
            outcome=AuditOutcome.FAILURE,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=current_user.tenant_id,
            details={"email": current_user.email, "reason": "invalid_totp_code"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP verification code. Please check your authenticator clock and try again.",
        )

    # Activation
    current_user.mfa_enabled = True
    current_user.mfa_enrolled_at = datetime.now(timezone.utc)
    current_user.last_totp_timestep = step - 1
    record_mfa_success(db, current_user, matched_timestep=step - 1)

    record_audit_event(
        db=db,
        action="MFA_ENROLL_COMPLETED",
        resource_type="user",
        resource_id=str(current_user.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={"email": current_user.email},
        request=request,
    )

    db.commit()
    return {"message": "MFA has been successfully verified and activated."}


@router.get("/status", response_model=MFAStatusResponse)
def get_mfa_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MFAStatusResponse:
    """
    Returns MFA enrollment status and remaining unused recovery codes.
    Never exposes enrolled secrets or recovery codes.
    """
    remaining = 0
    if current_user.mfa_enabled:
        remaining = db.scalar(
            select(func.count())
            .select_from(UserRecoveryCode)
            .where(UserRecoveryCode.user_id == current_user.id, UserRecoveryCode.is_used == False)
        ) or 0

    return MFAStatusResponse(
        mfa_enabled=current_user.mfa_enabled,
        enrolled_at=current_user.mfa_enrolled_at,
        recovery_codes_remaining=remaining,
    )


@router.post("/disable")
def disable_mfa(
    data: MFADisableRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """
    Disables MFA. Requires password reauthentication and valid TOTP code.
    Invalidates all recovery codes and enrolled secret.
    """
    if not current_user.mfa_enabled or not current_user.totp_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not currently enabled.")

    if not verify_password(data.password, current_user.password_hash):
        record_audit_event(
            db=db,
            action="MFA_DISABLE_FAILED",
            resource_type="user",
            resource_id=str(current_user.id),
            outcome=AuditOutcome.FAILURE,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=current_user.tenant_id,
            details={"email": current_user.email, "reason": "invalid_password"},
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password.")

    check_mfa_lockout(current_user)

    secret = decrypt_totp_secret(current_user.totp_secret_encrypted)
    is_valid, step = verify_totp_code(secret, data.totp_code, current_user.last_totp_timestep)

    if not is_valid:
        record_mfa_failure(db, current_user)
        record_audit_event(
            db=db,
            action="MFA_DISABLE_FAILED",
            resource_type="user",
            resource_id=str(current_user.id),
            outcome=AuditOutcome.FAILURE,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=current_user.tenant_id,
            details={"email": current_user.email, "reason": "invalid_totp_code"},
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP verification code.")

    # Disable MFA and purge credentials
    current_user.mfa_enabled = False
    current_user.totp_secret_encrypted = None
    current_user.mfa_enrolled_at = None
    current_user.last_totp_timestep = None
    db.execute(delete(UserRecoveryCode).where(UserRecoveryCode.user_id == current_user.id))

    record_mfa_success(db, current_user)

    record_audit_event(
        db=db,
        action="MFA_DISABLED",
        resource_type="user",
        resource_id=str(current_user.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={"email": current_user.email},
        request=request,
    )

    db.commit()
    return {"message": "MFA has been successfully disabled."}


@router.post("/recovery-codes/regenerate", response_model=MFARecoveryCodesResponse)
def regenerate_recovery_codes(
    data: MFARegenerateRecoveryCodesRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MFARecoveryCodesResponse:
    """
    Regenerates backup recovery codes. Invalidates previous codes.
    Requires password reauthentication and valid TOTP code.
    """
    if not current_user.mfa_enabled or not current_user.totp_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not currently enabled.")

    if not verify_password(data.password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password.")

    check_mfa_lockout(current_user)

    secret = decrypt_totp_secret(current_user.totp_secret_encrypted)
    is_valid, step = verify_totp_code(secret, data.totp_code, current_user.last_totp_timestep)

    if not is_valid:
        record_mfa_failure(db, current_user)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP verification code.")

    # Invalidate old codes
    db.execute(delete(UserRecoveryCode).where(UserRecoveryCode.user_id == current_user.id))

    # Generate new codes
    new_codes = generate_recovery_codes(10)
    for code in new_codes:
        db.add(UserRecoveryCode(user_id=current_user.id, code_hash=hash_recovery_code(code), is_used=False))

    record_mfa_success(db, current_user, matched_timestep=step)

    record_audit_event(
        db=db,
        action="MFA_RECOVERY_CODES_REGENERATED",
        resource_type="user",
        resource_id=str(current_user.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={"email": current_user.email, "count": len(new_codes)},
        request=request,
    )

    db.commit()
    return MFARecoveryCodesResponse(recovery_codes=new_codes)


@router.post("/verify-login", response_model=TokenResponse)
def verify_mfa_login(
    data: MFAVerifyLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """
    Completes two-stage login for MFA-enabled accounts.
    Consumes a short-lived mfa_challenge token and a valid TOTP code or single-use recovery code.
    Returns fully authenticated session access token.
    """
    try:
        user_id = decode_mfa_challenge_token(data.mfa_token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired MFA challenge token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.scalar(select(User).where(User.id == user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or inactive account.")

    if not user.mfa_enabled or not user.totp_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled on this account.")

    check_mfa_lockout(user)

    is_verified = False
    matched_step = None
    verification_method = "TOTP"

    if data.totp_code:
        secret = decrypt_totp_secret(user.totp_secret_encrypted)
        is_verified, matched_step = verify_totp_code(secret, data.totp_code, user.last_totp_timestep)
    elif data.recovery_code:
        verification_method = "RECOVERY_CODE"
        is_verified = verify_and_consume_recovery_code(db, user, data.recovery_code)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'totp_code' or 'recovery_code' must be provided.",
        )

    if not is_verified:
        record_mfa_failure(db, user)
        record_audit_event(
            db=db,
            action="MFA_VERIFY_FAILED",
            resource_type="user",
            resource_id=str(user.id),
            outcome=AuditOutcome.FAILURE,
            actor_user=user,
            actor_type=ActorType.USER,
            tenant_id=user.tenant_id,
            details={"email": user.email, "method": verification_method},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid {verification_method} verification code.",
        )

    # Revoke challenge token to prevent replay
    revoke_token(data.mfa_token)

    record_mfa_success(db, user, matched_timestep=matched_step)
    user.last_login_at = datetime.now(timezone.utc)

    record_audit_event(
        db=db,
        action="MFA_VERIFY_SUCCESS",
        resource_type="user",
        resource_id=str(user.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=user,
        actor_type=ActorType.USER,
        tenant_id=user.tenant_id,
        details={"email": user.email, "method": verification_method},
        request=request,
    )

    db.commit()

    return TokenResponse(
        access_token=create_access_token(user.id),
        token_type="bearer",
        mfa_required=False,
    )


@router.post("/step-up", response_model=MFAStepUpResponse)
def create_step_up_authorization(
    data: MFAStepUpRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MFAStepUpResponse:
    """
    Issues a short-lived step-up authorization token bound to the authenticated user
    and privileged action/target after fresh TOTP or recovery code verification.
    """
    if not current_user.mfa_enabled or not current_user.totp_secret_encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled on this account. Step-up authorization requires an enrolled MFA factor.",
        )

    check_mfa_lockout(current_user)

    is_verified = False
    matched_step = None
    method = "TOTP"

    if data.totp_code:
        secret = decrypt_totp_secret(current_user.totp_secret_encrypted)
        is_verified, matched_step = verify_totp_code(secret, data.totp_code, current_user.last_totp_timestep)
    elif data.recovery_code:
        method = "RECOVERY_CODE"
        is_verified = verify_and_consume_recovery_code(db, current_user, data.recovery_code)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either 'totp_code' or 'recovery_code' must be provided for step-up verification.",
        )

    if not is_verified:
        record_mfa_failure(db, current_user)
        record_audit_event(
            db=db,
            action="STEP_UP_FAILED",
            resource_type="user",
            resource_id=str(current_user.id),
            outcome=AuditOutcome.FAILURE,
            actor_user=current_user,
            actor_type=ActorType.USER,
            tenant_id=current_user.tenant_id,
            details={"email": current_user.email, "action": data.action, "target_id": str(data.target_id) if data.target_id else None},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid {method} verification code for step-up verification.",
        )

    record_mfa_success(db, current_user, matched_timestep=matched_step)

    step_up_tok = create_step_up_token(current_user.id, action=data.action, target_id=data.target_id)

    record_audit_event(
        db=db,
        action="STEP_UP_VERIFIED",
        resource_type="user",
        resource_id=str(current_user.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=current_user,
        actor_type=ActorType.USER,
        tenant_id=current_user.tenant_id,
        details={"email": current_user.email, "action": data.action, "method": method},
        request=request,
    )

    db.commit()

    return MFAStepUpResponse(
        step_up_token=step_up_tok,
        expires_in_seconds=300,
        action=data.action,
    )
