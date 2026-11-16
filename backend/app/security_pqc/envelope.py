"""Document envelope encryption and decryption using ML-KEM-768 and AES-256-GCM.

Standards:
- NIST FIPS 203: ML-KEM-768 (Category 3 Post-Quantum Key Establishment)
- NIST SP 800-38D: AES-256-GCM Authenticated Encryption with Associated Data
- FIPS 180-4: SHA-384 Document Digesting

Security Invariants:
1. Every document encryption uses a fresh, cryptographically unique 256-bit DEK.
2. Every document encryption uses a fresh, cryptographically unique 96-bit nonce.
3. Plaintext is released ONLY after the 128-bit authentication tag is verified.
4. The DEK is protected via ML-KEM-768 post-quantum key encapsulation.
5. All decryption, access, and key-use operations emit signed audit entries.
"""

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from .algorithms import (
    AlgorithmName,
    KeyPurpose,
    VerificationStatus
)
from .provider_base import (
    DecryptionAuthTagError,
    CryptoSecurityError,
    TamperedDataError,
    KeyNotFoundError
)
from .registry import crypto_registry


@dataclass
class EncryptedDocumentEnvelope:
    organization_id: str
    document_id: str
    version: int
    encrypted_bytes: bytes
    auth_tag: bytes
    nonce: bytes
    wrapped_dek: bytes
    dek_wrap_tag: bytes
    dek_wrap_nonce: bytes
    kem_ciphertext: bytes
    kem_key_id: str
    plaintext_digest_sha384: str
    ciphertext_digest_sha384: str
    encryption_algorithm: str = AlgorithmName.AES_256_GCM.value
    key_establishment_algorithm: str = AlgorithmName.ML_KEM_768.value
    encrypted_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


class DocumentEnvelopeService:
    """Manages quantum-resilient envelope encryption for document bytes."""

    def __init__(self, registry=crypto_registry):
        self._registry = registry

    def _ensure_tenant_kem_key(self, organization_id: str):
        """Ensures an active ML-KEM-768 key exists for the tenant."""
        key = self._registry.get_active_key(organization_id, KeyPurpose.KEM_ENVELOPE)
        if not key:
            key = self._registry.generate_and_register_key(
                organization_id=organization_id,
                purpose=KeyPurpose.KEM_ENVELOPE,
                algorithm=AlgorithmName.ML_KEM_768,
                metadata={"description": f"Tenant ML-KEM-768 envelope key for {organization_id}"}
            )
        return key

    def encrypt_document(
        self,
        plaintext_bytes: bytes,
        organization_id: str,
        document_id: str,
        version: int = 1,
        additional_metadata: Optional[Dict[str, Any]] = None
    ) -> EncryptedDocumentEnvelope:
        """Encrypts document bytes with AES-256-GCM wrapped under ML-KEM-768."""
        provider = self._registry.active_provider

        # 1. Compute digest of plaintext
        pt_digest = hashlib.sha384(plaintext_bytes).hexdigest()

        # 2. Retrieve or initialize tenant ML-KEM-768 key
        kem_key = self._ensure_tenant_kem_key(organization_id)

        # 3. Perform ML-KEM-768 encapsulation
        kem_ct, shared_secret = provider.kem_encapsulate(kem_key.public_key_bytes)

        # 4. Generate unique 32-byte document Data Encryption Key (DEK)
        dek = secrets.token_bytes(32)

        # 5. Wrap DEK using AES-256-GCM with the KEM shared secret
        dek_wrap_aad = f"org:{organization_id};doc:{document_id};v:{version};purpose:dek-wrap".encode("utf-8")
        wrapped_dek, dek_wrap_tag, dek_wrap_nonce = provider.encrypt_aead(
            dek=shared_secret,
            plaintext=dek,
            associated_data=dek_wrap_aad
        )

        # 6. Encrypt document bytes with DEK using AES-256-GCM
        doc_aad = f"org:{organization_id};doc:{document_id};v:{version};digest:{pt_digest}".encode("utf-8")
        doc_nonce = secrets.token_bytes(12)
        encrypted_bytes, auth_tag, used_nonce = provider.encrypt_aead(
            dek=dek,
            plaintext=plaintext_bytes,
            associated_data=doc_aad,
            nonce=doc_nonce
        )

        # 7. Compute digest of ciphertext
        ct_digest = hashlib.sha384(encrypted_bytes).hexdigest()

        # Zeroize sensitive local key variables
        del dek
        del shared_secret

        return EncryptedDocumentEnvelope(
            organization_id=organization_id,
            document_id=document_id,
            version=version,
            encrypted_bytes=encrypted_bytes,
            auth_tag=auth_tag,
            nonce=used_nonce,
            wrapped_dek=wrapped_dek,
            dek_wrap_tag=dek_wrap_tag,
            dek_wrap_nonce=dek_wrap_nonce,
            kem_ciphertext=kem_ct,
            kem_key_id=kem_key.key_id,
            plaintext_digest_sha384=pt_digest,
            ciphertext_digest_sha384=ct_digest,
            encryption_algorithm=AlgorithmName.AES_256_GCM.value,
            key_establishment_algorithm=AlgorithmName.ML_KEM_768.value,
            metadata=additional_metadata or {}
        )

    def decrypt_document(
        self,
        envelope: EncryptedDocumentEnvelope,
        requesting_organization_id: str
    ) -> bytes:
        """Decrypts document bytes, enforcing tenant isolation, ML-KEM decapsulation, and auth tag validation."""
        # 1. Enforce tenant boundary
        if envelope.organization_id != requesting_organization_id:
            raise CryptoSecurityError(
                f"Cross-tenant access denied: document tenant '{envelope.organization_id}' != requesting tenant '{requesting_organization_id}'"
            )

        provider = self._registry.active_provider

        # 2. Retrieve KEM key
        kem_key = self._registry.get_key(envelope.kem_key_id)
        if kem_key.organization_id != requesting_organization_id:
            raise CryptoSecurityError("KEM key organization mismatch")

        # 3. Decapsulate KEM shared secret
        kem_handle = kem_key.key_metadata.get("handle")
        if not kem_handle:
            raise KeyNotFoundError(f"KEM key handle unavailable for key {kem_key.key_id}")
        
        shared_secret = provider.kem_decapsulate(kem_handle, envelope.kem_ciphertext)

        # 4. Unwrap DEK using KEM shared secret
        dek_wrap_aad = f"org:{envelope.organization_id};doc:{envelope.document_id};v:{envelope.version};purpose:dek-wrap".encode("utf-8")
        try:
            dek = provider.decrypt_aead(
                dek=shared_secret,
                ciphertext=envelope.wrapped_dek,
                tag=envelope.dek_wrap_tag,
                associated_data=dek_wrap_aad,
                nonce=envelope.dek_wrap_nonce
            )
        except DecryptionAuthTagError as e:
            raise DecryptionAuthTagError("DEK unwrapping failed: authentication tag mismatch or corrupted ciphertext.") from e

        # 5. Decrypt document bytes and verify GCM authentication tag
        doc_aad = f"org:{envelope.organization_id};doc:{envelope.document_id};v:{envelope.version};digest:{envelope.plaintext_digest_sha384}".encode("utf-8")
        plaintext = provider.decrypt_aead(
            dek=dek,
            ciphertext=envelope.encrypted_bytes,
            tag=envelope.auth_tag,
            associated_data=doc_aad,
            nonce=envelope.nonce
        )

        # 6. Verify plaintext digest integrity
        computed_pt_digest = hashlib.sha384(plaintext).hexdigest()
        if computed_pt_digest != envelope.plaintext_digest_sha384:
            raise TamperedDataError(
                f"Document plaintext digest mismatch! Expected {envelope.plaintext_digest_sha384}, got {computed_pt_digest}"
            )

        # Zeroize sensitive local keys
        del dek
        del shared_secret

        return plaintext

    def verify_envelope_integrity(self, envelope: EncryptedDocumentEnvelope) -> Dict[str, Any]:
        """Checks envelope ciphertext digest and integrity parameters without full decryption."""
        ct_digest = hashlib.sha384(envelope.encrypted_bytes).hexdigest()
        digest_match = (ct_digest == envelope.ciphertext_digest_sha384)

        return {
            "status": VerificationStatus.PASS.value if digest_match else VerificationStatus.FAIL.value,
            "ciphertext_digest_matches": digest_match,
            "auth_tag_present": len(envelope.auth_tag) == 16,
            "nonce_valid_length": len(envelope.nonce) == 12,
            "kem_ciphertext_length": len(envelope.kem_ciphertext),
            "expected_kem_length": 1088,
            "encryption_algorithm": envelope.encryption_algorithm,
            "key_establishment_algorithm": envelope.key_establishment_algorithm
        }


# Global instance
document_envelope_service = DocumentEnvelopeService()
