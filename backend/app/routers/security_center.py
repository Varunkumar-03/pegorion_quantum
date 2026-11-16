"""FastAPI Router for Quantum-Resilient Security Center.

Exposes live backend endpoints for Module E:
- Cryptographic inventory and configured algorithms
- Real runtime self-tests and benchmarks
- Key management lifecycle (generation, rotation, revocation)
- Document envelope encryption status & verification
- Evidence Vault, hash-linked audit chain, and Merkle checkpoints
- Organization security policy and legal holds

RULE: Every status comes from real backend checks. Allowed states:
PASS, FAIL, NOT CONFIGURED, NOT TESTED, VERIFICATION UNAVAILABLE.
Never display fabricated counts, test results or green success indicators.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..core.database import get_db
from ..models.identity import User
from ..security import get_current_user
from ..routers.documents import get_optional_user

from ..security_pqc.algorithms import (
    AlgorithmName,
    VerificationStatus,
    KeyPurpose,
    KeyLifecycleStatus
)
from ..security_pqc.registry import crypto_registry
from ..security_pqc.envelope import document_envelope_service
from ..security_pqc.manifest import manifest_signing_service
from ..security_pqc.audit_vault import evidence_vault_service
from ..security_pqc.policy import tenant_policy_service, DocumentClassification

router = APIRouter(prefix="/security", tags=["quantum_security_center"])


class KeyGenerateRequest(BaseModel):
    algorithm: AlgorithmName
    purpose: KeyPurpose
    description: Optional[str] = None


class KeyRevokeRequest(BaseModel):
    reason: str


class LegalHoldRequest(BaseModel):
    action: str = Field(..., description="'apply' or 'release'")
    reason: Optional[str] = None


class PolicyUpdateRequest(BaseModel):
    signing_policy: Optional[str] = None
    retention_period_days: Optional[int] = None


@router.get("/inventory")
def get_cryptographic_inventory():
    """Returns runtime cryptographic inventory, parameters, and active provider info."""
    return crypto_registry.get_inventory()


@router.get("/self-tests")
def run_runtime_self_tests():
    """Runs live cryptographic self-tests across all algorithms and returns actual results."""
    return crypto_registry.run_self_tests()


@router.get("/benchmarks")
def get_benchmarks():
    """Measures and returns latency, memory, key sizes, and ciphertext sizes on this platform."""
    return crypto_registry.run_benchmarks()


@router.get("/keys")
def list_keys(
    current_user: User = Depends(get_optional_user)
):
    """Lists registered cryptographic keys for current tenant."""
    keys = crypto_registry.list_keys(organization_id=current_user.organization_id)
    return [
        {
            "key_id": k.key_id,
            "organization_id": k.organization_id,
            "algorithm": k.algorithm,
            "purpose": k.purpose.value,
            "version": k.version,
            "status": k.status.value,
            "created_at": k.created_at.isoformat(),
            "rotated_at": k.rotated_at.isoformat() if k.rotated_at else None,
            "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
            "public_key_bytes_len": len(k.public_key_bytes),
            "public_key_fingerprint": k.public_key_bytes[:8].hex() + "...",
            "provider": k.key_metadata.get("provider", "TestOnlyLocalProvider")
        }
        for k in keys
    ]


@router.post("/keys/generate")
def generate_key(
    req: KeyGenerateRequest,
    current_user: User = Depends(get_optional_user)
):
    """Generates a new cryptographic key for the organization."""
    record = crypto_registry.generate_and_register_key(
        organization_id=current_user.organization_id,
        purpose=req.purpose,
        algorithm=req.algorithm,
        metadata={"description": req.description or f"Manual generation for {req.purpose.value}"}
    )
    
    # Record audit event
    evidence_vault_service.append_event(
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="key_generated",
        resource_id=record.key_id,
        resource_type="cryptographic_key",
        payload={"algorithm": record.algorithm, "purpose": record.purpose.value, "version": record.version}
    )

    return {
        "status": "success",
        "key_id": record.key_id,
        "algorithm": record.algorithm,
        "version": record.version,
        "created_at": record.created_at.isoformat()
    }


@router.post("/keys/{key_id}/rotate")
def rotate_key(
    key_id: str,
    current_user: User = Depends(get_optional_user)
):
    """Rotates an existing key to a new version."""
    key = crypto_registry.get_key(key_id)
    if key.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")

    new_key = crypto_registry.rotate_key(
        organization_id=current_user.organization_id,
        purpose=key.purpose
    )

    evidence_vault_service.append_event(
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="key_rotated",
        resource_id=new_key.key_id,
        resource_type="cryptographic_key",
        payload={"previous_key_id": key_id, "new_version": new_key.version}
    )

    return {
        "status": "success",
        "previous_key_id": key_id,
        "new_key_id": new_key.key_id,
        "version": new_key.version
    }


@router.post("/keys/{key_id}/revoke")
def revoke_key(
    key_id: str,
    req: KeyRevokeRequest,
    current_user: User = Depends(get_optional_user)
):
    """Revokes a cryptographic key."""
    key = crypto_registry.get_key(key_id)
    if key.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")

    revoked = crypto_registry.revoke_key(key_id, reason=req.reason)

    evidence_vault_service.append_event(
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="key_revoked",
        resource_id=key_id,
        resource_type="cryptographic_key",
        payload={"reason": req.reason}
    )

    return {
        "status": "success",
        "key_id": key_id,
        "status_state": revoked.status.value,
        "revoked_at": revoked.revoked_at.isoformat()
    }


@router.get("/vault/events")
def list_audit_events(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_optional_user)
):
    """Retrieves signed audit events for the tenant."""
    return evidence_vault_service.list_events(organization_id=current_user.organization_id, limit=limit)


@router.get("/vault/checkpoints")
def list_checkpoints(
    current_user: User = Depends(get_optional_user)
):
    """Retrieves Merkle-tree checkpoints with SLH-DSA archival signatures."""
    return evidence_vault_service.list_checkpoints(organization_id=current_user.organization_id)


@router.post("/vault/checkpoint")
def create_checkpoint(
    current_user: User = Depends(get_optional_user)
):
    """Triggers generation of a Merkle checkpoint and signs with SLH-DSA & ML-DSA."""
    checkpoint = evidence_vault_service.create_checkpoint(organization_id=current_user.organization_id)
    return {
        "status": "success",
        "checkpoint_id": checkpoint.checkpoint_id,
        "merkle_root_sha512": checkpoint.merkle_root_sha512,
        "event_count": checkpoint.event_count,
        "slhdsa_signature_present": bool(checkpoint.slhdsa_signature_hex),
        "mldsa_signature_present": bool(checkpoint.mldsa_signature_hex),
        "rfc3161_status": checkpoint.rfc3161_token.get("status") if checkpoint.rfc3161_token else "NOT CONFIGURED"
    }


@router.get("/vault/verify")
def verify_audit_vault(
    current_user: User = Depends(get_optional_user)
):
    """Verifies audit chain integrity, hash linkages, and Merkle checkpoint roots."""
    report = evidence_vault_service.verify_audit_vault(organization_id=current_user.organization_id)
    return {
        "status": report.status.value,
        "total_events_checked": report.total_events_checked,
        "total_checkpoints_checked": report.total_checkpoints_checked,
        "hash_chain_intact": report.hash_chain_intact,
        "merkle_roots_verified": report.merkle_roots_verified,
        "signatures_verified": report.signatures_verified,
        "missing_events": report.missing_events,
        "altered_events": report.altered_events,
        "reordered_events": report.reordered_events,
        "unverifiable_events": report.unverifiable_events,
        "summary": report.summary_message
    }


@router.get("/policy")
def get_security_policy(
    current_user: User = Depends(get_optional_user)
):
    """Retrieves cryptographic policy, retention rules, and legal hold state."""
    policy = tenant_policy_service.get_or_create_policy(current_user.organization_id)
    return policy.__dict__


@router.post("/policy")
def update_security_policy(
    req: PolicyUpdateRequest,
    current_user: User = Depends(get_optional_user)
):
    """Updates organization cryptographic policy."""
    policy = tenant_policy_service.update_policy(
        organization_id=current_user.organization_id,
        signing_policy=req.signing_policy,
        retention_period_days=req.retention_period_days
    )
    return policy.__dict__


@router.post("/policy/legal-hold")
def manage_legal_hold(
    req: LegalHoldRequest,
    current_user: User = Depends(get_optional_user)
):
    """Applies or releases a legal hold for the tenant."""
    if req.action == "apply":
        if not req.reason:
            raise HTTPException(status_code=400, detail="Reason required to apply legal hold")
        policy = tenant_policy_service.apply_legal_hold(
            organization_id=current_user.organization_id,
            reason=req.reason,
            initiated_by=current_user.id
        )
        evidence_vault_service.append_event(
            organization_id=current_user.organization_id,
            actor_id=current_user.id,
            action="legal_hold_applied",
            resource_id=current_user.organization_id,
            resource_type="organization_policy",
            payload={"reason": req.reason}
        )
    elif req.action == "release":
        policy = tenant_policy_service.release_legal_hold(current_user.organization_id)
        evidence_vault_service.append_event(
            organization_id=current_user.organization_id,
            actor_id=current_user.id,
            action="legal_hold_released",
            resource_id=current_user.organization_id,
            resource_type="organization_policy",
            payload={}
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid action: choose 'apply' or 'release'")

    return policy.__dict__

