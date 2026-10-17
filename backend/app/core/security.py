from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings

password_hasher = PasswordHasher()
_revoked_tokens: set[str] = set()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return password_hasher.check_needs_rehash(password_hash)


def create_access_token(user_id: UUID) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "jti": str(uuid4()),
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def revoke_token(token: str) -> None:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "exp", "iat"]},
        )
        jti = payload.get("jti") or token
        _revoked_tokens.add(jti)
    except jwt.PyJWTError:
        _revoked_tokens.add(token)


def is_token_revoked(token: str) -> bool:
    if token in _revoked_tokens:
        return True
    settings = get_settings()
    try:
        # Decode without verifying expiration to check jti
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_exp": False},
        )
        return payload.get("jti") in _revoked_tokens
    except jwt.PyJWTError:
        return False


def decode_access_token(token: str) -> UUID:
    if is_token_revoked(token):
        raise jwt.InvalidTokenError("Token has been revoked")
    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["sub", "exp", "iat"]},
    )
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Unexpected token type")
    return UUID(payload["sub"])


def create_mfa_challenge_token(user_id: UUID) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "jti": str(uuid4()),
        "type": "mfa_challenge",
        "iat": now,
        "exp": now + timedelta(minutes=settings.mfa_challenge_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_mfa_challenge_token(token: str) -> UUID:
    if is_token_revoked(token):
        raise jwt.InvalidTokenError("Challenge token has already been consumed or revoked")
    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["sub", "exp", "iat"]},
    )
    if payload.get("type") != "mfa_challenge":
        raise jwt.InvalidTokenError("Unexpected token type for MFA challenge")
    return UUID(payload["sub"])


def create_step_up_token(user_id: UUID, action: str, target_id: UUID | None = None) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "jti": str(uuid4()),
        "type": "mfa_step_up",
        "action": action,
        "target_id": str(target_id) if target_id else None,
        "iat": now,
        "exp": now + timedelta(minutes=settings.mfa_step_up_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def verify_and_consume_step_up_token(
    token: str,
    expected_user_id: UUID,
    expected_action: str,
    expected_target_id: UUID | None = None,
) -> None:
    if is_token_revoked(token):
        raise jwt.InvalidTokenError("Step-up token has already been consumed or revoked")
    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"require": ["sub", "exp", "iat"]},
    )
    if payload.get("type") != "mfa_step_up":
        raise jwt.InvalidTokenError("Unexpected token type for step-up verification")
    if UUID(payload["sub"]) != expected_user_id:
        raise jwt.InvalidTokenError("Step-up token is bound to a different user")
    if payload.get("action") != expected_action:
        raise jwt.InvalidTokenError(f"Step-up token action mismatch (expected '{expected_action}', got '{payload.get('action')}')")
    if payload.get("target_id") is not None and (expected_target_id is None or str(expected_target_id) != payload.get("target_id")):
        raise jwt.InvalidTokenError("Step-up token is bound to a different target resource")
    revoke_token(token)
