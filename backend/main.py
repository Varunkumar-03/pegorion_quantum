"""Pegorion Quantum-Resilient Security Platform API.

NIST FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA-65), FIPS 205 (SLH-DSA-SHA2-128f),
NIST SP 800-38D (AES-256-GCM), Canonical JSON Manifests, and Evidence Vault.
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routers import auth, documents, security_center

app = FastAPI(
    title="Pegorion Quantum-Resilient Security API",
    version="1.0.0",
    description="Provider-independent quantum-resilient security service, envelope encryption, and Evidence Vault",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
allowed_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Core Quantum Security & Document Routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(documents.router, prefix="/api/v1")
app.include_router(security_center.router, prefix="/api/v1")

@app.get("/")
def root():
    """API root endpoint."""
    return {
        "name": "Pegorion Quantum-Resilient Security API",
        "version": "1.0.0",
        "standard": "NIST FIPS 203, FIPS 204, FIPS 205, NIST SP 800-38D",
        "message": "Quantum-Resilient Security Foundation Active"
    }

@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "quantum-security-platform"}

@app.get("/api/v1/")
def api_root():
    """Available quantum security API endpoints."""
    return {
        "api_version": "1.0.0",
        "endpoints": [
            "/api/v1/security/algorithms",
            "/api/v1/security/keys",
            "/api/v1/security/keys/generate",
            "/api/v1/security/keys/rotate",
            "/api/v1/security/verify/envelope",
            "/api/v1/security/verify/manifest",
            "/api/v1/security/evidence-vault/events",
            "/api/v1/security/evidence-vault/checkpoint",
            "/api/v1/security/evidence-vault/verify-integrity",
            "/api/v1/security/policy/evaluate",
            "/api/v1/security/benchmarks",
            "/api/v1/security/self-test",
            "/api/v1/documents",
            "/api/v1/documents/upload"
        ]
    }
