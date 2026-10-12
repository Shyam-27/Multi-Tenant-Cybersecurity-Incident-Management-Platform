from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(tags=["health"])

class HealthResponse(BaseModel):
    status: Literal["ok"]
    database: Literal["ok"]

@router.get("/health", response_model=HealthResponse, summary="Verify API and database health")
def health_check(db: Session = Depends(get_db)) -> HealthResponse:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable") from exc
    return HealthResponse(status="ok", database="ok")
