from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "SEA Security Scanner"
    VERSION: str = "2.0.0"
    DEBUG: bool = False

    DATABASE_URL: str = "sqlite:///./data/scanner.db"
    REPORTS_DIR: str = "reports"
    LOGS_DIR: str = "logs"

    MAX_WORKERS: int = 5
    REQUEST_TIMEOUT: int = 10
    MAX_PAGES: int = 30

    FRONTEND_URL: str = "http://localhost:5173"
    BACKEND_CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
