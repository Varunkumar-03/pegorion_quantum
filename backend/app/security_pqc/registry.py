"""Cryptographic registry, inventory, and lifecycle coordinator.

Maintains:
- Active provider instances (Local and Cloud KMS)
- Key records and lifecycle tracking (generation, activation, rotation, revocation)
- Cryptographic inventory and parameter sets
- Real runtime benchmarks and platform telemetry
- Live self-test execution
"""

import sys
import platform
import time
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from uuid import uuid4

from .algorithms import (
    AlgorithmName,
    VerificationStatus,
    ALGORITHM_METADATA,
    KeyPurpose,
    KeyLifecycleStatus
)
from .provider_base import (
    CryptoProviderBase,
    KeyRecord,
    SelfTestResult,
    ProviderInfo,
    CryptoSecurityError,
    KeyNotFoundError
)
from .test_provider import TestOnlyLocalProvider
from .cloud_kms_provider import CloudKMSProvider


class CryptoRegistry:
    """Singleton registry coordinating cryptographic providers and key lifecycle."""

    def __init__(self):
        self._local_provider = TestOnlyLocalProvider()
        self._kms_provider = CloudKMSProvider()
        
        # Primary provider selection (falls back to local development provider)
        self._active_provider: CryptoProviderBase = (
            self._kms_provider if self._kms_provider.is_available() else self._local_provider
        )

        # In-memory key metadata registry: key_id -> KeyRecord
        # In production this reflects the versioned database table
        self._keys: Dict[str, KeyRecord] = {}

        # Tenant active key pointers: (org_id, purpose) -> active key_id
        self._tenant_active_keys: Dict[Tuple[str, str], str] = {}

    @property
    def active_provider(self) -> CryptoProviderBase:
        return self._active_provider

    @property
    def local_provider(self) -> TestOnlyLocalProvider:
        return self._local_provider

    @property
    def kms_provider(self) -> CloudKMSProvider:
        return self._kms_provider

    def set_active_provider(self, provider_name: str) -> None:
        if provider_name == self._kms_provider.name:
            if not self._kms_provider.is_available():
                raise CryptoSecurityError("Cloud KMS provider is NOT CONFIGURED.")
            self._active_provider = self._kms_provider
        elif provider_name == self._local_provider.name:
            self._active_provider = self._local_provider
        else:
            raise ValueError(f"Unknown provider: {provider_name}")

    # --- Key Lifecycle Management (Module A) ---
    def generate_and_register_key(
        self,
        organization_id: str,
        purpose: KeyPurpose,
        algorithm: AlgorithmName,
        metadata: Optional[Dict[str, Any]] = None
    ) -> KeyRecord:
        """Generates a keypair, creates an immutable versioned record, and marks it active."""
        key_id = f"key-{organization_id[:8]}-{purpose.value}-{uuid4().hex[:8]}"
        
        if algorithm == AlgorithmName.ML_KEM_768:
            pub_bytes, handle = self._active_provider.kem_generate_keypair()
        elif algorithm in (AlgorithmName.ML_DSA_65, AlgorithmName.SLH_DSA_SHA2_128F, AlgorithmName.ED25519):
            pub_bytes, handle = self._active_provider.sign_generate_keypair(algorithm)
        else:
            raise ValueError(f"Unsupported algorithm for key generation: {algorithm}")

        # Determine version
        existing_versions = [
            k.version for k in self._keys.values()
            if k.organization_id == organization_id and k.purpose == purpose
        ]
        version = max(existing_versions, default=0) + 1

        record = KeyRecord(
            key_id=key_id,
            organization_id=organization_id,
            algorithm=algorithm.value,
            purpose=purpose,
            version=version,
            created_at=datetime.now(timezone.utc),
            status=KeyLifecycleStatus.ACTIVE,
            public_key_bytes=pub_bytes,
            key_metadata={
                **(metadata or {}),
                "handle": handle,
                "provider": self._active_provider.name
            }
        )

        # If there was an active key for this org/purpose, rotate it
        tenant_key_tuple = (organization_id, purpose.value)
        if tenant_key_tuple in self._tenant_active_keys:
            old_key_id = self._tenant_active_keys[tenant_key_tuple]
            if old_key_id in self._keys:
                old_key = self._keys[old_key_id]
                old_key.status = KeyLifecycleStatus.ROTATED
                old_key.rotated_at = datetime.now(timezone.utc)

        self._keys[key_id] = record
        self._tenant_active_keys[tenant_key_tuple] = key_id
        return record

    def get_active_key(self, organization_id: str, purpose: KeyPurpose) -> Optional[KeyRecord]:
        """Returns the currently active key for an organization and purpose."""
        key_id = self._tenant_active_keys.get((organization_id, purpose.value))
        if key_id and key_id in self._keys:
            return self._keys[key_id]
        return None

    def get_key(self, key_id: str) -> KeyRecord:
        """Retrieves key record by ID."""
        if key_id not in self._keys:
            raise KeyNotFoundError(f"Key record not found: {key_id}")
        return self._keys[key_id]

    def rotate_key(self, organization_id: str, purpose: KeyPurpose) -> KeyRecord:
        """Rotates key: generates a new version and transitions previous key to ROTATED status."""
        current_active = self.get_active_key(organization_id, purpose)
        if not current_active:
            raise KeyNotFoundError(f"No active key found to rotate for org '{organization_id}' and purpose '{purpose.value}'")
        
        algo = AlgorithmName(current_active.algorithm)
        return self.generate_and_register_key(
            organization_id=organization_id,
            purpose=purpose,
            algorithm=algo,
            metadata={"rotated_from": current_active.key_id}
        )

    def revoke_key(self, key_id: str, reason: str) -> KeyRecord:
        """Revokes a key, recording revocation timestamp and reason."""
        record = self.get_key(key_id)
        record.status = KeyLifecycleStatus.REVOKED
        record.revoked_at = datetime.now(timezone.utc)
        record.revocation_reason = reason
        
        # Remove from active tenant pointers if active
        tenant_key_tuple = (record.organization_id, record.purpose.value)
        if self._tenant_active_keys.get(tenant_key_tuple) == key_id:
            del self._tenant_active_keys[tenant_key_tuple]
        return record

    def list_keys(self, organization_id: Optional[str] = None) -> List[KeyRecord]:
        """Lists key records, optionally filtered by organization."""
        if organization_id:
            return [k for k in self._keys.values() if k.organization_id == organization_id]
        return list(self._keys.values())

    # --- Runtime Diagnostics & Inventory ---
    def get_inventory(self) -> Dict[str, Any]:
        """Returns comprehensive cryptographic inventory and parameter sets."""
        return {
            "algorithms": ALGORITHM_METADATA,
            "standards_compliance": {
                "FIPS_203": "ML-KEM-768 implemented (Category 3 parameter set)",
                "FIPS_204": "ML-DSA-65 implemented (Category 3 parameter set)",
                "FIPS_205": "SLH-DSA-SHA2-128f implemented (archival hash-based signatures)",
                "NIST_SP_800_38D": "AES-256-GCM AEAD implemented",
                "RFC_8032": "Ed25519 classical hybrid component",
                "RFC_7748": "X25519 classical key exchange"
            },
            "terminology_notice": (
                "ML-KEM-768 and ML-DSA-65 are NIST security category 3 parameter sets. "
                "The numbers 768 and 65 are not bit-security claims. No algorithm is unbreakable "
                "or guaranteed secure forever."
            ),
            "platform_runtime": {
                "python_version": sys.version.split()[0],
                "platform": platform.platform(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "architecture": platform.architecture()[0]
            },
            "providers": [
                self._local_provider.get_info().__dict__,
                self._kms_provider.get_info().__dict__
            ],
            "active_provider": self._active_provider.name
        }

    def run_self_tests(self) -> Dict[str, Any]:
        """Executes live self-tests across active providers."""
        local_tests = self._local_provider.run_self_tests()
        kms_tests = self._kms_provider.run_self_tests()

        all_tests = {**local_tests, **kms_tests}
        
        # Determine aggregate status
        has_fail = any(t.status == VerificationStatus.FAIL for t in all_tests.values())
        all_pass = all(t.status == VerificationStatus.PASS for t in local_tests.values())
        
        overall_status = VerificationStatus.FAIL if has_fail else (
            VerificationStatus.PASS if all_pass else VerificationStatus.NOT_TESTED
        )

        return {
            "overall_status": overall_status.value,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "results": {
                algo: {
                    "algorithm": t.algorithm,
                    "status": t.status.value,
                    "passed": t.passed,
                    "latency_ms": t.latency_ms,
                    "error_message": t.error_message,
                    "details": t.details
                }
                for algo, t in all_tests.items()
            }
        }

    def run_benchmarks(self) -> Dict[str, Any]:
        """Runs benchmarks on latency, memory, key sizes, ciphertext sizes, and signature sizes."""
        benchmarks = {}

        # 1. ML-KEM-768
        t_keygen_start = time.perf_counter()
        ek, hdl = self._local_provider.kem_generate_keypair()
        t_keygen = (time.perf_counter() - t_keygen_start) * 1000

        t_encaps_start = time.perf_counter()
        ct, ss1 = self._local_provider.kem_encapsulate(ek)
        t_encaps = (time.perf_counter() - t_encaps_start) * 1000

        t_decaps_start = time.perf_counter()
        ss2 = self._local_provider.kem_decapsulate(hdl, ct)
        t_decaps = (time.perf_counter() - t_decaps_start) * 1000

        benchmarks[AlgorithmName.ML_KEM_768.value] = {
            "standard": "NIST FIPS 203",
            "category": "NIST Category 3",
            "keygen_latency_ms": round(t_keygen, 3),
            "encaps_latency_ms": round(t_encaps, 3),
            "decaps_latency_ms": round(t_decaps, 3),
            "public_key_bytes": len(ek),
            "ciphertext_bytes": len(ct),
            "shared_secret_bytes": len(ss1)
        }

        # 2. ML-DSA-65
        t_sig_gen_start = time.perf_counter()
        pk_dsa, hdl_dsa = self._local_provider.sign_generate_keypair(AlgorithmName.ML_DSA_65)
        t_sig_gen = (time.perf_counter() - t_sig_gen_start) * 1000

        msg = b"Pegorion Benchmark Payload 1KB" * 32
        t_sign_start = time.perf_counter()
        sig_dsa = self._local_provider.sign(hdl_dsa, msg, AlgorithmName.ML_DSA_65)
        t_sign = (time.perf_counter() - t_sign_start) * 1000

        t_verify_start = time.perf_counter()
        valid_dsa = self._local_provider.verify(pk_dsa, msg, sig_dsa, AlgorithmName.ML_DSA_65)
        t_verify = (time.perf_counter() - t_verify_start) * 1000

        benchmarks[AlgorithmName.ML_DSA_65.value] = {
            "standard": "NIST FIPS 204",
            "category": "NIST Category 3",
            "keygen_latency_ms": round(t_sig_gen, 3),
            "sign_latency_ms": round(t_sign, 3),
            "verify_latency_ms": round(t_verify, 3),
            "public_key_bytes": len(pk_dsa),
            "signature_bytes": len(sig_dsa),
            "valid": valid_dsa
        }

        # 3. SLH-DSA-SHA2-128f
        t_slh_gen_start = time.perf_counter()
        pk_slh, hdl_slh = self._local_provider.sign_generate_keypair(AlgorithmName.SLH_DSA_SHA2_128F)
        t_slh_gen = (time.perf_counter() - t_slh_gen_start) * 1000

        t_slh_sign_start = time.perf_counter()
        sig_slh = self._local_provider.sign(hdl_slh, msg, AlgorithmName.SLH_DSA_SHA2_128F)
        t_slh_sign = (time.perf_counter() - t_slh_sign_start) * 1000

        t_slh_verify_start = time.perf_counter()
        valid_slh = self._local_provider.verify(pk_slh, msg, sig_slh, AlgorithmName.SLH_DSA_SHA2_128F)
        t_slh_verify = (time.perf_counter() - t_slh_verify_start) * 1000

        benchmarks[AlgorithmName.SLH_DSA_SHA2_128F.value] = {
            "standard": "NIST FIPS 205",
            "category": "NIST Category 1 (SHA2-128f)",
            "keygen_latency_ms": round(t_slh_gen, 3),
            "sign_latency_ms": round(t_slh_sign, 3),
            "verify_latency_ms": round(t_slh_verify, 3),
            "public_key_bytes": len(pk_slh),
            "signature_bytes": len(sig_slh),
            "valid": valid_slh
        }

        # 4. AES-256-GCM AEAD (1MB synthetic document throughput)
        sample_doc = b"0123456789ABCDEF" * 65536  # 1 MB
        dek = secrets.token_bytes(32)
        aad = b"tenant:vb-001;purpose:benchmark"

        t_enc_start = time.perf_counter()
        ct_doc, tag_doc, nonce_doc = self._local_provider.encrypt_aead(dek, sample_doc, aad)
        t_enc = (time.perf_counter() - t_enc_start) * 1000

        t_dec_start = time.perf_counter()
        pt_doc = self._local_provider.decrypt_aead(dek, ct_doc, tag_doc, aad, nonce_doc)
        t_dec = (time.perf_counter() - t_dec_start) * 1000

        benchmarks[AlgorithmName.AES_256_GCM.value] = {
            "standard": "NIST SP 800-38D",
            "payload_bytes": len(sample_doc),
            "encrypt_latency_1mb_ms": round(t_enc, 3),
            "decrypt_latency_1mb_ms": round(t_dec, 3),
            "key_bytes": len(dek),
            "nonce_bytes": len(nonce_doc),
            "tag_bytes": len(tag_doc)
        }

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python_version": sys.version.split()[0],
            "benchmarks": benchmarks
        }


# Global registry instance
crypto_registry = CryptoRegistry()
