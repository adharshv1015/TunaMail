import os
from dotenv import load_dotenv


load_dotenv()


class Settings:

    APP_NAME = os.getenv(
        "APP_NAME",
        "TunaMail"
    )

    ENVIRONMENT = os.getenv(
        "ENVIRONMENT",
        "development"
    )

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "fallback_secret_for_dev_only_change_in_prod"
    )

    SESSION_MAX_AGE = int(os.getenv(
        "SESSION_MAX_AGE",
        "86400"
    ))

    SESSION_COOKIE_SECURE = os.getenv(
        "SESSION_COOKIE_SECURE",
        "false"
    ).lower() == "true"

    ALLOWED_ORIGINS = [
        origin.strip() 
        for origin in os.getenv(
            "ALLOWED_ORIGINS", 
            "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",") 
        if origin.strip()
    ]


settings = Settings()
