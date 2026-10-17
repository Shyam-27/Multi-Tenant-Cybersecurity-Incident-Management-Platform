from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.destinations import router as destinations_router
from app.api.evidence import router as evidence_router
from app.api.health import router as health_router
from app.api.incidents import router as incident_router
from app.api.iocs import router as iocs_router
from app.api.mfa import router as mfa_router
from app.api.playbooks import router as playbooks_router
from app.api.tenants import router as tenant_router
from app.api.users import router as user_router
from app.core.config import get_settings

settings = get_settings()
app = FastAPI(title="SentinelOps API", version="0.7.0", docs_url="/docs", redoc_url="/redoc")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-MFA-Code", "X-Step-Up-Token"],
)

# Root-level health check
app.include_router(health_router)

# Versioned API routes
app.include_router(health_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(mfa_router, prefix="/api/v1")
app.include_router(tenant_router, prefix="/api/v1")
app.include_router(user_router, prefix="/api/v1")
app.include_router(incident_router, prefix="/api/v1")
app.include_router(evidence_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(iocs_router, prefix="/api/v1")
app.include_router(destinations_router, prefix="/api/v1")
app.include_router(playbooks_router, prefix="/api/v1")
