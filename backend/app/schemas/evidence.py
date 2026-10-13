from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    incident_id: UUID
    uploaded_by_id: UUID
    uploaded_by_name: str | None = None
    filename: str
    file_size_bytes: int
    sha256_hash: str
    mime_type: str
    description: str
    created_at: datetime
