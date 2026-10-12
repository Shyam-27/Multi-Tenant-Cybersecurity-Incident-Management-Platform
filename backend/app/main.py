from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.tenants import router as tenant_router
from app.api.users import router as user_router
from app.core.config import get_settings

settings = get_settings()
app = FastAPI(title="SentinelOps API", version="0.2.0", docs_url="/docs", redoc_url="/redoc")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Root-level health check
app.include_router(health_router)

# Versioned API routes
app.include_router(health_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(tenant_router, prefix="/api/v1")
app.include_router(user_router, prefix="/api/v1")
