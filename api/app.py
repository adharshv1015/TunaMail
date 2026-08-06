from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from api.auth import router as auth_router
from api.config import settings
from api.gmail import router as gmail_router

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="AI powered email threat analysis platform"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.get("/")
def home():

    return {
        "application": "TunaMail",
        "status": "running"
    }
