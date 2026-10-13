"""SpyAware-Analyzer FastAPI Application Entrypoint.

Defines the FastAPI application, CORS middleware, API routing,
and local startup configuration.
"""

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.api.router import router as api_router
from backend.services.analysis_service import InvalidAPKError

app = FastAPI(
    title="SpyAware Analyzer",
    description="Defensive Android APK analysis platform for indicators of covert surveillance.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

@app.exception_handler(InvalidAPKError)
def invalid_apk_exception_handler(request: Request, exc: InvalidAPKError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": f"Invalid APK file: {str(exc)}"},
    )

# CORS setup for web dashboard and potential local clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",  # Local development flexibility
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/")
def root():
    return {
        "platform": "SpyAware Analyzer",
        "tagline": "Android Covert Surveillance Analysis Platform",
        "status": "online",
        "docs": "/docs",
        "health": "/api/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
