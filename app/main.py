"""
Main FastAPI application for Scrambled Eggs.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.endpoints import auth

app = FastAPI(
    title="Scrambled Eggs API",
    description="Backend API for Scrambled Eggs application",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(
    auth.router,
    prefix=f"{settings.API_V1_STR}/auth",
    tags=["Authentication"]
)

@app.get("/")
def read_root():
    return {"message": "Welcome to Scrambled Eggs API"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
