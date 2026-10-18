from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = Field(validation_alias="DATABASE_URL")
    jwt_secret_key: str = Field(min_length=32, validation_alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", validation_alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, ge=5, le=1440, validation_alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    cors_origins: list[str] = Field(default_factory=list, validation_alias="CORS_ORIGINS")
    upload_dir: str = Field(default="uploads", validation_alias="UPLOAD_DIR")
    max_upload_size: int = Field(default=10485760, validation_alias="MAX_UPLOAD_SIZE")  # 10 MiB

    # Phase 6: Threat Intelligence Feeds
    virustotal_api_key: str | None = Field(default=None, validation_alias="VIRUSTOTAL_API_KEY")
    alienvault_otx_api_key: str | None = Field(default=None, validation_alias="ALIENVAULT_OTX_API_KEY")
    abuseipdb_api_key: str | None = Field(default=None, validation_alias="ABUSEIPDB_API_KEY")
    threat_intel_cache_ttl_minutes: int = Field(default=60, ge=1, le=1440, validation_alias="THREAT_INTEL_CACHE_TTL_MINUTES")

    # Phase 6: SIEM & Webhook Dispatcher
    allow_local_webhooks: bool = Field(default=False, validation_alias="ALLOW_LOCAL_WEBHOOKS")
    webhook_timeout_seconds: int = Field(default=10, ge=2, le=60, validation_alias="WEBHOOK_TIMEOUT_SECONDS")
    webhook_max_retries: int = Field(default=5, ge=1, le=10, validation_alias="WEBHOOK_MAX_RETRIES")

    # Phase 7A: MFA & Privileged-Action Security
    mfa_encryption_key: str | None = Field(default=None, validation_alias="MFA_ENCRYPTION_KEY")
    mfa_challenge_expire_minutes: int = Field(default=5, ge=1, le=30, validation_alias="MFA_CHALLENGE_EXPIRE_MINUTES")
    mfa_step_up_expire_minutes: int = Field(default=5, ge=1, le=30, validation_alias="MFA_STEP_UP_EXPIRE_MINUTES")

    # Phase 7B: Durable Background Processing & Scheduled Jobs
    celery_broker_url: str = Field(default="redis://redis:6379/0", validation_alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://redis:6379/1", validation_alias="CELERY_RESULT_BACKEND")
    redis_url: str = Field(default="redis://redis:6379/0", validation_alias="REDIS_URL")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", enable_decoding=False)

    @field_validator("jwt_secret_key")
    @classmethod
    def reject_insecure_jwt_secret(cls, value: str) -> str:
        if "replace" in value.lower() or "change-this" in value.lower():
            raise ValueError("JWT_SECRET_KEY must be a unique generated secret")
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_cors_origins(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

@lru_cache
def get_settings() -> Settings:
    return Settings()
