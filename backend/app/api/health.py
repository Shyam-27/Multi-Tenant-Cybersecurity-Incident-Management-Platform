import logging
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.database import get_db

logger = logging.getLogger("sentinelops.health")
router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"]
    database: Literal["ok"]


class LivenessResponse(BaseModel):
    status: Literal["ok"]


class ReadinessResponse(BaseModel):
    status: Literal["ok"]
    database: Literal["ok"]
    redis: Literal["ok", "disabled"]


@router.get("/health", response_model=HealthResponse, summary="Verify API and database health")
def health_check(db: Session = Depends(get_db)) -> HealthResponse:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable") from exc
    return HealthResponse(status="ok", database="ok")


@router.get("/health/live", response_model=LivenessResponse, summary="Process liveness probe")
def liveness_check() -> LivenessResponse:
    return LivenessResponse(status="ok")


@router.get("/health/ready", response_model=ReadinessResponse, summary="Application readiness probe")
def readiness_check(db: Session = Depends(get_db)) -> ReadinessResponse:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable") from exc

    settings = get_settings()
    redis_status: Literal["ok", "disabled"] = "disabled"
    if settings.redis_url and not settings.redis_url.startswith("sqlite"):
        try:
            import redis

            r = redis.from_url(settings.redis_url, socket_timeout=1.5)
            r.ping()
            redis_status = "ok"
        except Exception as exc:
            logger.warning("Redis readiness check failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Redis broker unavailable: {exc}",
            ) from exc

    return ReadinessResponse(status="ok", database="ok", redis=redis_status)
