"""Canonical document manifests and hybrid digital signatures.

Standards:
- NIST FIPS 204: ML-DSA-65 Post-Quantum Digital Signature Algorithm (Category 3)
- RFC 8032: Ed25519 Classical Digital Signature
- FIPS 180-4: SHA-384 Digesting

Security Invariant:
Hybrid signing uses separately verifiable classical and post-quantum signatures
over the exact same canonical JSON manifest. No proprietary composite signature
format is invented. Each signature is independently verifiable.
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from .algorithms import (
    AlgorithmName,
    VerificationStatus,
    KeyPurpose
)
from .provider_base import (
    CryptoSecurityError,
    SignatureVerificationError
)
from .registry import crypto_registry


@dataclass
class ManifestSignature:
    algorithm: str
    key_id: str
    public_key_hex: str
    signature_hex: str
    signed_at: str
    signature_type: str  # "post_quantum" or "classical"


@dataclass
class CanonicalManifest:
    manifest_version: str
    organization_id: str
    document_id: str
    document_version: int
    document_digest_sha384: str
    source_metadata: Dict[str, Any]
    encryption_reference: Dict[str, Any]
    provenance: Dict[str, Any]
    created_at: str
    signatures: List[ManifestSignature] = field(default_factory=list)

    def canonical_bytes(self) -> bytes:
        """Returns deterministic, canonical byte representation of the unsigned manifest.
        Sorted keys, minimal separators (',', ':'), UTF-8 encoded.
        """
        payload = {
            "manifest_version": self.manifest_version,
            "organization_id": self.organization_id,
            "document_id": self.document_id,
            "document_version": self.document_version,
            "document_digest_sha384": self.document_digest_sha384,
            "source_metadata": self.source_metadata,
            "encryption_reference": self.encryption_reference,
            "provenance": self.provenance,
            "created_at": self.created_at
        }
        canonical_str = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        return canonical_str.encode('utf-8')

    def canonical_digest_sha384(self) -> str:
        """Computes SHA-384 digest over canonical manifest bytes."""
        return hashlib.sha384(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["canonical_digest_sha384"] = self.canonical_digest_sha384()
        return d


@dataclass
class ManifestVerificationReport:
    status: VerificationStatus
    manifest_digest: str
    pqc_signature_verified: bool
    classical_signature_verified: bool
    policy_enforced: str  # "hybrid", "pqc_only", "classical_only"
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


class ManifestSigningService:
    """Creates, signs, and independently verifies canonical document manifests."""

    def __init__(self, registry=crypto_registry):
        self._registry = registry

    def _ensure_tenant_signing_keys(self, organization_id: str):
        """Ensures active ML-DSA-65 and Ed25519 signing keys exist for the tenant."""
        mldsa_key = self._registry.get_active_key(organization_id, KeyPurpose.MANIFEST_SIGNING)
        if not mldsa_key:
            mldsa_key = self._registry.generate_and_register_key(
                organization_id=organization_id,
                purpose=KeyPurpose.MANIFEST_SIGNING,
                algorithm=AlgorithmName.ML_DSA_65,
                metadata={"description": f"Tenant ML-DSA-65 manifest signing key for {organization_id}"}
            )

        ed25519_key = self._registry.get_active_key(organization_id, KeyPurpose.HYBRID_CLASSICAL_SIGNING)
        if not ed25519_key:
            ed25519_key = self._registry.generate_and_register_key(
                organization_id=organization_id,
                purpose=KeyPurpose.HYBRID_CLASSICAL_SIGNING,
                algorithm=AlgorithmName.ED25519,
                metadata={"description": f"Tenant Ed25519 hybrid classical signing key for {organization_id}"}
            )

        return mldsa_key, ed25519_key

    def create_and_sign_manifest(
        self,
        organization_id: str,
        document_id: str,
        document_version: int,
        document_digest_sha384: str,
        source_metadata: Dict[str, Any],
        encryption_reference: Dict[str, Any],
        provenance: Dict[str, Any],
        policy: str = "hybrid"  # "hybrid", "pqc_only", "classical_only"
    ) -> CanonicalManifest:
        """Constructs canonical manifest and attaches independently verifiable signatures."""
        manifest = CanonicalManifest(
            manifest_version="1.0",
            organization_id=organization_id,
            document_id=document_id,
            document_version=document_version,
            document_digest_sha384=document_digest_sha384,
            source_metadata=source_metadata,
            encryption_reference=encryption_reference,
            provenance=provenance,
            created_at=datetime.now(timezone.utc).isoformat()
        )

        canonical_data = manifest.canonical_bytes()
        provider = self._registry.active_provider
        mldsa_key, ed25519_key = self._ensure_tenant_signing_keys(organization_id)

        signatures: List[ManifestSignature] = []

        # 1. Post-quantum ML-DSA-65 signature
        if policy in ("hybrid", "pqc_only"):
            mldsa_handle = mldsa_key.key_metadata.get("handle")
            pqc_sig_bytes = provider.sign(mldsa_handle, canonical_data, AlgorithmName.ML_DSA_65)
            signatures.append(
                ManifestSignature(
                    algorithm=AlgorithmName.ML_DSA_65.value,
                    key_id=mldsa_key.key_id,
                    public_key_hex=mldsa_key.public_key_bytes.hex(),
                    signature_hex=pqc_sig_bytes.hex(),
                    signed_at=datetime.now(timezone.utc).isoformat(),
                    signature_type="post_quantum"
                )
            )

        # 2. Classical Ed25519 signature
        if policy in ("hybrid", "classical_only"):
            ed_handle = ed25519_key.key_metadata.get("handle")
            ed_sig_bytes = provider.sign(ed_handle, canonical_data, AlgorithmName.ED25519)
            signatures.append(
                ManifestSignature(
                    algorithm=AlgorithmName.ED25519.value,
                    key_id=ed25519_key.key_id,
                    public_key_hex=ed25519_key.public_key_bytes.hex(),
                    signature_hex=ed_sig_bytes.hex(),
                    signed_at=datetime.now(timezone.utc).isoformat(),
                    signature_type="classical"
                )
            )

        manifest.signatures = signatures
        return manifest

    def verify_manifest(
        self,
        manifest: CanonicalManifest,
        required_policy: str = "hybrid"
    ) -> ManifestVerificationReport:
        """Verifies signatures over the canonical manifest according to policy."""
        canonical_data = manifest.canonical_bytes()
        canonical_digest = manifest.canonical_digest_sha384()
        provider = self._registry.active_provider

        pqc_verified = False
        classical_verified = False
        sig_checks: Dict[str, Any] = {}

        for sig in manifest.signatures:
            pub_bytes = bytes.fromhex(sig.public_key_hex)
            sig_bytes = bytes.fromhex(sig.signature_hex)

            if sig.algorithm == AlgorithmName.ML_DSA_65.value:
                valid = provider.verify(pub_bytes, canonical_data, sig_bytes, AlgorithmName.ML_DSA_65)
                pqc_verified = valid
                sig_checks[sig.algorithm] = {"verified": valid, "key_id": sig.key_id}

            elif sig.algorithm == AlgorithmName.ED25519.value:
                valid = provider.verify(pub_bytes, canonical_data, sig_bytes, AlgorithmName.ED25519)
                classical_verified = valid
                sig_checks[sig.algorithm] = {"verified": valid, "key_id": sig.key_id}

        # Policy validation
        if required_policy == "hybrid":
            overall_pass = pqc_verified and classical_verified
        elif required_policy == "pqc_only":
            overall_pass = pqc_verified
        elif required_policy == "classical_only":
            overall_pass = classical_verified
        else:
            overall_pass = False

        status = VerificationStatus.PASS if overall_pass else VerificationStatus.FAIL

        return ManifestVerificationReport(
            status=status,
            manifest_digest=canonical_digest,
            pqc_signature_verified=pqc_verified,
            classical_signature_verified=classical_verified,
            policy_enforced=required_policy,
            details=sig_checks,
            error_message=None if overall_pass else f"Signature verification failed for policy '{required_policy}'"
        )


# Global instance
manifest_signing_service = ManifestSigningService()

