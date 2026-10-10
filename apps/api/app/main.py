from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.routers.github import router as github_router
from app.routers.scans import router as scans_router
from app.schemas import HealthResponse

app = FastAPI(
    title="Raksa API",
    description="Autonomous application security analysis and remediation prototype.",
    version="0.1.0",
    docs_url="/docs",
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site="lax",
    https_only=settings.app_env == "production",
    session_cookie="raksa_session",
    max_age=60 * 60 * 8,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)
app.include_router(github_router)
app.include_router(scans_router)


@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    from app.services.github_app import github_app
    from app.services.nebius import nebius
    from app.services.tavily import tavily
    return HealthResponse(
        status="ok", app="raksa",
        integrations={
            "github_app": github_app.configured,
            "nebius_token_factory": nebius.configured,
            "tavily": tavily.configured,
            "sandbox_nebius": settings.sandbox_provider == "nebius",
            "sandbox_docker": settings.sandbox_provider == "docker",
        },
    )
