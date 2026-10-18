from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.incident import IncidentSeverity, IncidentStatus
from app.models.ioc import IndicatorType, ThreatVerdict
from app.models.playbook import PlaybookTrigger

VALID_TRIGGER_EVENTS = {t.value for t in PlaybookTrigger}
VALID_SEVERITIES = {s.value for s in IncidentSeverity}
VALID_STATUSES = {st.value for st in IncidentStatus}
VALID_IOC_TYPES = {it.value for it in IndicatorType}
VALID_VERDICTS = {v.value for v in ThreatVerdict}


def validate_playbook_trigger_conditions(trigger_event: str, conditions: dict[str, Any] | None) -> dict[str, Any]:
    if trigger_event not in VALID_TRIGGER_EVENTS:
        raise ValueError(f"Invalid trigger_event '{trigger_event}'. Supported: {sorted(VALID_TRIGGER_EVENTS)}")

    if not conditions:
        return {}

    allowed_keys = {"min_severity", "incident_statuses", "ioc_types", "ioc_verdict", "cooldown_seconds"}
    unrecognized = set(conditions.keys()) - allowed_keys
    if unrecognized:
        raise ValueError(f"Unsupported trigger condition keys: {sorted(unrecognized)}")

    if "min_severity" in conditions and conditions["min_severity"] is not None:
        sev = str(conditions["min_severity"]).upper().strip()
        if sev not in VALID_SEVERITIES:
            raise ValueError(f"Invalid min_severity '{sev}'. Supported: {sorted(VALID_SEVERITIES)}")
        conditions["min_severity"] = sev

    if "incident_statuses" in conditions and conditions["incident_statuses"] is not None:
        statuses = conditions["incident_statuses"]
        if not isinstance(statuses, list):
            raise ValueError("incident_statuses must be a list")
        validated_statuses = []
        for s in statuses:
            st = str(s).upper().strip()
            if st not in VALID_STATUSES:
                raise ValueError(f"Invalid incident status '{st}'. Supported: {sorted(VALID_STATUSES)}")
            validated_statuses.append(st)
        conditions["incident_statuses"] = validated_statuses

    if "ioc_types" in conditions and conditions["ioc_types"] is not None:
        ioc_types = conditions["ioc_types"]
        if not isinstance(ioc_types, list):
            raise ValueError("ioc_types must be a list")
        validated_types = []
        for t in ioc_types:
            it = str(t).upper().strip()
            if it not in VALID_IOC_TYPES:
                raise ValueError(f"Invalid ioc_type '{it}'. Supported: {sorted(VALID_IOC_TYPES)}")
            validated_types.append(it)
        conditions["ioc_types"] = validated_types

    if "ioc_verdict" in conditions and conditions["ioc_verdict"] is not None:
        verd = str(conditions["ioc_verdict"]).upper().strip()
        if verd not in VALID_VERDICTS:
            raise ValueError(f"Invalid ioc_verdict '{verd}'. Supported: {sorted(VALID_VERDICTS)}")
        conditions["ioc_verdict"] = verd

    return conditions


class CreatePlaybookRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    trigger_event: str = Field(default="MANUAL", description="MANUAL, INCIDENT_CRITICAL, MALICIOUS_IOC_DETECTED, RULE_MATCH")
    actions: list[dict[str, Any]] = Field(description="List of action definitions")
    is_enabled: bool = Field(default=True)
    is_dry_run: bool = Field(default=True)
    requires_approval: bool = Field(default=True)
    trigger_conditions: dict[str, Any] = Field(default_factory=dict)
    cooldown_seconds: int = Field(default=300, ge=0, le=86400)

    @field_validator("trigger_conditions")
    @classmethod
    def validate_conditions(cls, v: dict[str, Any], info: Any) -> dict[str, Any]:
        trigger_event = info.data.get("trigger_event", "MANUAL")
        return validate_playbook_trigger_conditions(trigger_event, v)


class UpdatePlaybookRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    trigger_event: str | None = None
    actions: list[dict[str, Any]] | None = None
    is_enabled: bool | None = None
    is_dry_run: bool | None = None
    requires_approval: bool | None = None
    trigger_conditions: dict[str, Any] | None = None
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)

    @field_validator("trigger_conditions")
    @classmethod
    def validate_conditions(cls, v: dict[str, Any] | None, info: Any) -> dict[str, Any] | None:
        if v is None:
            return None
        trigger_event = info.data.get("trigger_event") or "MANUAL"
        return validate_playbook_trigger_conditions(trigger_event, v)


class TriggerExecutionRequest(BaseModel):
    incident_id: UUID | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    override_dry_run: bool | None = None
    mfa_code: str | None = Field(default=None, description="Fresh TOTP or recovery code for live execution")
    step_up_token: str | None = Field(default=None, description="Step-up token from /auth/mfa/step-up")


class ApprovalDecisionRequest(BaseModel):
    notes: str | None = Field(default=None, max_length=1000)
    mfa_code: str | None = Field(default=None, description="Fresh TOTP or recovery code for live approval")
    step_up_token: str | None = Field(default=None, description="Step-up token from /auth/mfa/step-up")


class PlaybookResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    name: str
    description: str
    trigger_event: str
    actions: list[dict[str, Any]]
    is_enabled: bool
    is_dry_run: bool
    requires_approval: bool
    trigger_conditions: dict[str, Any]
    rule_version: int
    cooldown_seconds: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApprovalResponse(BaseModel):
    id: UUID
    status: str
    required_role: str
    decided_by_id: UUID | None
    decision_notes: str | None
    decided_at: datetime | None
    step_up_verified_at: datetime | None = None
    step_up_method: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ExecutionResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    playbook_id: UUID
    incident_id: UUID | None
    triggered_by_id: UUID
    trigger_source: str
    trigger_event_id: str | None = None
    trigger_reason: str | None = None
    status: str
    is_dry_run: bool
    parameters: dict[str, Any]
    step_results: list[dict[str, Any]]
    error_summary: str | None
    created_at: datetime
    completed_at: datetime | None
    step_up_verified_at: datetime | None = None
    step_up_method: str | None = None
    approval: ApprovalResponse | None = None

    model_config = ConfigDict(from_attributes=True)


class ExecutionListResponse(BaseModel):
    items: list[ExecutionResponse]
    total: int
    page: int
    page_size: int
    pages: int
