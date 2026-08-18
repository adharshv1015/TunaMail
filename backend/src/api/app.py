from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import HTTPException as FastAPIHTTPException

import logging
import traceback

from src.api.routes import router
from src.api.auth import router as auth_router
from src.api.config import settings
from src.api.gmail import router as gmail_router
from src.api.reports import router as reports_router
from src.api.system import router as system_router
from src.api.intelligence import router as intelligence_router


logger = logging.getLogger(__name__)


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="AI powered email threat analysis platform"
)


# ============================================================
# 1. Session Middleware
# ============================================================

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    max_age=settings.SESSION_MAX_AGE,
    same_site="lax",
    https_only=settings.SESSION_COOKIE_SECURE
)


# ============================================================
# 2. CORS Middleware
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# 3. Security Headers Middleware
# ============================================================

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if settings.SESSION_COOKIE_SECURE:
        response.headers[
            "Strict-Transport-Security"
        ] = "max-age=31536000; includeSubDomains"

    return response


# ============================================================
# 4. Global Exception Handler
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):

    # Let FastAPI/Starlette handle known HTTP exceptions normally.
    if isinstance(exc, (StarletteHTTPException, FastAPIHTTPException)):
        raise exc

    logger.error(
        f"Unexpected error: {exc}\n{traceback.format_exc()}"
    )

    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Internal Server Error"
        }
    )


# ============================================================
# 5. Application Routers
# ============================================================

app.include_router(router)


app.include_router(
    auth_router,
    prefix="/auth",
    tags=["Authentication"]
)


app.include_router(
    gmail_router,
    prefix="/gmail",
    tags=["Gmail"]
)


app.include_router(
    reports_router,
    prefix="/report",
    tags=["Reports"]
)


app.include_router(
    system_router,
    prefix="/system",
    tags=["System"]
)


app.include_router(
    intelligence_router,
    prefix="/intelligence",
    tags=["Intelligence"]
)


# ============================================================
# 6. Root Endpoint
# ============================================================

@app.get("/")
def home():
    return {
        "application": "TunaMail",
        "status": "running"
    }