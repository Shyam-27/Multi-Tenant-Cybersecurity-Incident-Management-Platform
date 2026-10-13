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
