from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class MFAEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code: str
    qr_code_svg: str | None = None
    recovery_codes: list[str]


class MFAConfirmEnrollRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=10)


class MFAStatusResponse(BaseModel):
    mfa_enabled: bool
    enrolled_at: datetime | None = None
    recovery_codes_remaining: int = 0


class MFADisableRequest(BaseModel):
    password: str = Field(min_length=8)
    totp_code: str = Field(min_length=6, max_length=10)


class MFARegenerateRecoveryCodesRequest(BaseModel):
    password: str = Field(min_length=8)
    totp_code: str = Field(min_length=6, max_length=10)


class MFARecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


class MFAVerifyLoginRequest(BaseModel):
    mfa_token: str = Field(min_length=10)
    totp_code: str | None = None
    recovery_code: str | None = None


class MFAStepUpRequest(BaseModel):
    totp_code: str | None = None
    recovery_code: str | None = None
    action: str = Field(default="playbook_approval")
    target_id: UUID | None = None


class MFAStepUpResponse(BaseModel):
    step_up_token: str
    expires_in_seconds: int
    action: str
