import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import logging
import secrets
from urllib.parse import quote
from uuid import UUID

from cryptography.fernet import Fernet
from fastapi import HTTPException, status
import pyotp
import qrcode
import qrcode.image.svg
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import ActorType, AuditOutcome
from app.models.user import User, UserRecoveryCode
from app.services.audit_service import record_audit_event

logger = logging.getLogger("sentinelops.mfa")


def get_mfa_fernet() -> Fernet:
    """
    Initializes a Fernet cipher instance using the configured MFA_ENCRYPTION_KEY.
    Raises ValueError if MFA_ENCRYPTION_KEY is missing or invalid.
    Never falls back to plaintext storage.
    """
    settings = get_settings()
    raw_key = settings.mfa_encryption_key
    if not raw_key or not raw_key.strip():
        raise ValueError(
            "MFA_ENCRYPTION_KEY is not configured. Encryption key must be provided via environment/configuration."
        )

    clean_key = raw_key.strip().encode("utf-8")
    try:
        decoded = base64.urlsafe_b64decode(clean_key)
        if len(decoded) == 32:
            return Fernet(clean_key)
    except Exception:
        pass

    # Deterministically derive standard 32-byte Fernet key via SHA-256
    derived = base64.urlsafe_b64encode(hashlib.sha256(clean_key).digest())
    return Fernet(derived)


def encrypt_totp_secret(secret: str) -> str:
    """Encrypts a plaintext TOTP secret for storage at rest in PostgreSQL."""
    fernet = get_mfa_fernet()
    return fernet.encrypt(secret.strip().encode("utf-8")).decode("utf-8")


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypts an encrypted TOTP secret from storage."""
    fernet = get_mfa_fernet()
    return fernet.decrypt(encrypted_secret.strip().encode("utf-8")).decode("utf-8")


def generate_totp_secret() -> str:
    """Generates a cryptographically random base32 TOTP secret (160-bit)."""
    return pyotp.random_base32(32)


def generate_provisioning_uri(secret: str, email: str, issuer: str = "SentinelOps") -> str:
    """Generates standards-compliant otpauth:// provisioning URI."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


get_provisioning_uri = generate_provisioning_uri


def generate_qr_code_svg(provisioning_uri: str) -> str:
    """Generates raw SVG string for safe, self-contained QR code rendering."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    stream = io.BytesIO()
    img.save(stream)
    return stream.getvalue().decode("utf-8")


def generate_qr_code_data_uri(raw_svg: str) -> str:
    """Wraps raw SVG in a data URI for direct img src rendering."""
    return f"data:image/svg+xml;utf8,{quote(raw_svg)}"


def verify_totp_code(secret: str, code: str, last_timestep: int | None = None) -> tuple[bool, int | None]:
    """
    Verifies a 6-digit TOTP code against a secret with a 1-step window (valid for +-30 seconds).
    Enforces replay defense: if the matching time step <= last_timestep, reject code.
    Returns: (is_valid, matched_time_step)
    """
    clean_code = str(code).strip().replace(" ", "").replace("-", "")
    if not clean_code.isdigit() or len(clean_code) != 6:
        return False, None

    totp = pyotp.TOTP(secret)
    now = datetime.now(timezone.utc)
    current_step = int(now.timestamp() // 30)

    for offset in (0, -1, 1):
        step = current_step + offset
        expected_code = totp.at(now + timedelta(seconds=offset * 30))
        if secrets.compare_digest(clean_code, expected_code):
            # Anti-replay protection
            if last_timestep is not None and step <= last_timestep:
                logger.warning("Rejected replayed TOTP time step %d (last accepted: %d)", step, last_timestep)
                return False, None
            return True, step

    return False, None


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Generates random single-use recovery codes in XXXXX-XXXXX format."""
    codes: list[str] = []
    for _ in range(count):
        token = secrets.token_hex(5).upper()
        codes.append(f"{token[:5]}-{token[5:]}")
    return codes


def hash_recovery_code(code: str) -> str:
    """Generates a salted SHA-256 hash for secure recovery code storage."""
    clean = str(code).strip().upper().replace(" ", "")
    settings = get_settings()
    salt = settings.jwt_secret_key[:16]
    return hashlib.sha256(f"{salt}:{clean}".encode("utf-8")).hexdigest()


def check_mfa_lockout(user: User) -> None:
    """Checks whether the user account is temporarily locked out of MFA verification."""
    if not user.mfa_locked_until:
        return
    now = datetime.now(timezone.utc)
    locked_until = user.mfa_locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    if locked_until > now:
        remaining_secs = int((locked_until - now).total_seconds())
        remaining_mins = max(1, (remaining_secs + 59) // 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"MFA verification temporarily locked due to excessive failed attempts. Please try again in {remaining_mins} minute(s).",
        )


def record_mfa_failure(db: Session, user: User) -> None:
    """Increments failed verification attempts and locks account if threshold exceeded."""
    user.mfa_failed_attempts = (user.mfa_failed_attempts or 0) + 1
    if user.mfa_failed_attempts >= 5:
        user.mfa_locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        logger.warning("User %s locked out of MFA for 15 minutes due to 5 consecutive failures", user.id)
    db.commit()


def record_mfa_success(db: Session, user: User, matched_timestep: int | None = None) -> None:
    """Resets failed verification attempts and updates anti-replay time step."""
    user.mfa_failed_attempts = 0
    user.mfa_locked_until = None
    if matched_timestep is not None:
        user.last_totp_timestep = matched_timestep
    db.commit()


def verify_and_consume_recovery_code(db: Session, user: User, code: str) -> bool:
    """
    Atomically searches, verifies, and marks a recovery code as consumed.
    Protects against concurrent race conditions via row-level locks.
    """
    target_hash = hash_recovery_code(code)
    # Query with row-level lock
    active_codes = db.scalars(
        select(UserRecoveryCode)
        .where(
            UserRecoveryCode.user_id == user.id,
            UserRecoveryCode.is_used == False,
        )
        .with_for_update()
    ).all()

    matched_code = None
    for item in active_codes:
        if secrets.compare_digest(item.code_hash, target_hash):
            matched_code = item
            break

    if not matched_code:
        return False

    matched_code.is_used = True
    matched_code.used_at = datetime.now(timezone.utc)

    record_audit_event(
        db=db,
        action="MFA_RECOVERY_CODE_CONSUMED",
        resource_type="user",
        resource_id=str(user.id),
        outcome=AuditOutcome.SUCCESS,
        actor_user=user,
        actor_type=ActorType.USER,
        tenant_id=user.tenant_id,
        details={"remaining_codes": len(active_codes) - 1},
    )
    db.commit()
    return True


def verify_step_up_mfa(
    db: Session,
    user: User,
    action: str,
    target_id: UUID | None,
    step_up_token: str | None = None,
    mfa_code: str | None = None,
) -> str:
    """
    Verifies step-up authorization for privileged actions via either a single-use
    step-up token or a fresh TOTP / recovery code.
    Returns: verified method ("STEP_UP_TOKEN", "TOTP", or "RECOVERY_CODE").
    Raises ValueError on failure.
    """
    from app.core.security import verify_and_consume_step_up_token

    if step_up_token:
        try:
            verify_and_consume_step_up_token(
                token=step_up_token,
                expected_user_id=user.id,
                expected_action=action,
                expected_target_id=target_id,
            )
            return "STEP_UP_TOKEN"
        except Exception as exc:
            record_audit_event(
                db=db,
                action="STEP_UP_FAILED",
                resource_type="user",
                resource_id=str(user.id),
                outcome=AuditOutcome.FAILURE,
                actor_user=user,
                actor_type=ActorType.USER,
                tenant_id=user.tenant_id,
                details={"reason": f"invalid_step_up_token: {exc}", "action": action},
            )
            db.commit()
            raise ValueError(f"Step-up MFA verification failed: {exc}") from exc

    elif mfa_code:
        if not user.mfa_enabled or not user.totp_secret_encrypted:
            record_audit_event(
                db=db,
                action="STEP_UP_FAILED",
                resource_type="user",
                resource_id=str(user.id),
                outcome=AuditOutcome.DENIED,
                actor_user=user,
                actor_type=ActorType.USER,
                tenant_id=user.tenant_id,
                details={"reason": "mfa_not_enrolled", "action": action},
            )
            db.commit()
            raise ValueError("Step-up MFA verification failed: User does not have MFA enabled.")

        check_mfa_lockout(user)
        secret = decrypt_totp_secret(user.totp_secret_encrypted)
        is_valid, step = verify_totp_code(secret, mfa_code, user.last_totp_timestep)
        if is_valid:
            record_mfa_success(db, user, matched_timestep=step)
            return "TOTP"

        if verify_and_consume_recovery_code(db, user, mfa_code):
            record_mfa_success(db, user)
            return "RECOVERY_CODE"

        record_mfa_failure(db, user)
        record_audit_event(
            db=db,
            action="STEP_UP_FAILED",
            resource_type="user",
            resource_id=str(user.id),
            outcome=AuditOutcome.FAILURE,
            actor_user=user,
            actor_type=ActorType.USER,
            tenant_id=user.tenant_id,
            details={"reason": "invalid_mfa_code", "action": action},
        )
        db.commit()
        raise ValueError("Step-up MFA verification failed: Invalid MFA verification code.")

    else:
        record_audit_event(
            db=db,
            action="STEP_UP_FAILED",
            resource_type="user",
            resource_id=str(user.id),
            outcome=AuditOutcome.DENIED,
            actor_user=user,
            actor_type=ActorType.USER,
            tenant_id=user.tenant_id,
            details={"reason": "missing_step_up_credentials", "action": action},
        )
        db.commit()
        raise ValueError("Step-up MFA verification required: Live response actions require verified MFA. Provide 'mfa_code' or 'step_up_token'.")

