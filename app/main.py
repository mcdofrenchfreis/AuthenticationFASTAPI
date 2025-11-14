from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .database import Base, engine, run_migrations
from .models import *  # noqa: F401,F403
from .auth import router as auth_router
from .web_routes import router as web_router
from .core.settings import settings


def create_app() -> FastAPI:
    app = FastAPI(title="Auth API", version="1.0.0")

    @app.on_event("startup")
    def on_startup():
        # Validate configuration for the current runtime environment
        settings.validate_for_runtime()
        Base.metadata.create_all(bind=engine)
        run_migrations()

    # Routers
    app.include_router(auth_router)
    app.include_router(web_router)

    # Static files for the web app
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    return app


# Backward-compatible module-level app
app = create_app()
