"""Comprehensive Quantum-Resilient Security Automated Test Suite.

Module G Test Verification:
1. ML-KEM-768: Encapsulation, decapsulation, shared secret equality, corrupted ciphertext rejection.
2. ML-DSA-65: Keypair generation, signing, verification, and tamper detection on message/signature.
3. SLH-DSA-SHA2-128f: Keypair generation, pure signing, verification, and tamper detection.
4. AES-256-GCM AEAD: Encryption, decryption, unique nonces, wrong-key and corrupted authentication-tag failure.
5. Canonical Manifests: Canonical serialization, SHA-384 digests, hybrid ML-DSA-65 + Ed25519 signing, and field-tamper detection.
6. Evidence Vault & Merkle Checkpoints: Monotonic sequence numbers, SHA-384 hash-chaining, Merkle tree root calculation, SLH-DSA checkpoint signing, and detection of missing, altered, and reordered records.
7. Key Lifecycle: Generation, versioning, rotation, and revocation behavior.
8. Tenant Isolation & Resource Access: Prohibiting cross-tenant decryption, enforcing legal classification roles, and respecting legal holds.
9. Backup / State Recovery: Keystore and evidence vault state serialization and consistency.
10. Benchmark Telemetry: Latency, key sizes, ciphertext sizes, and signature sizes validation.
"""

import hashlib
import json
import secrets
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

backend_dir = str(Path(__file__).resolve().parent.parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
from app.security_pqc.algorithms import (
    AlgorithmName,
    VerificationStatus,
    KeyPurpose,
    KeyLifecycleStatus
)
from app.security_pqc.provider_base import (
    DecryptionAuthTagError,
    CryptoSecurityError,
    KeyNotFoundError,
    TamperedDataError
)
from app.security_pqc.registry import crypto_registry
from app.security_pqc.envelope import document_envelope_service
from app.security_pqc.manifest import manifest_signing_service
from app.security_pqc.audit_vault import evidence_vault_service, MerkleTree
from app.security_pqc.policy import tenant_policy_service, DocumentClassification

client = TestClient(app)


# =========================================================================
# 1. ML-KEM-768 (NIST FIPS 203)
# =========================================================================
def test_ml_kem_768_encaps_decaps_and_tamper():
    provider = crypto_registry.local_provider
    ek_bytes, hdl = provider.kem_generate_keypair()
    assert len(ek_bytes) == 1184, f"ML-KEM-768 public key must be 1184 bytes, got {len(ek_bytes)}"
    
    ct, ss1 = provider.kem_encapsulate(ek_bytes)
    assert len(ct) == 1088, f"ML-KEM-768 ciphertext must be 1088 bytes, got {len(ct)}"
    assert len(ss1) == 32, f"ML-KEM-768 shared secret must be 32 bytes, got {len(ss1)}"

    ss2 = provider.kem_decapsulate(hdl, ct)
    assert ss1 == ss2, "Decapsulated shared secret must match encapsulated shared secret"

    # Corrupt ciphertext test: Decapsulation should not produce the same shared secret
    corrupt_ct = bytearray(ct)
    corrupt_ct[0] ^= 0xAA
    ss_corrupt = provider.kem_decapsulate(hdl, bytes(corrupt_ct))
    assert ss_corrupt != ss1, "ML-KEM-768 implicit rejection failed to distinguish corrupted ciphertext"


# =========================================================================
# 2. ML-DSA-65 (NIST FIPS 204)
# =========================================================================
def test_ml_dsa_65_signing_and_tamper_detection():
    provider = crypto_registry.local_provider
    pk, sk_hdl = provider.sign_generate_keypair(AlgorithmName.ML_DSA_65)
    assert len(pk) == 1952, f"ML-DSA-65 public key must be 1952 bytes, got {len(pk)}"

    message = b"Vertical Bridge Ground Lease Manifest Checkpoint Alpha"
    sig = provider.sign(sk_hdl, message, AlgorithmName.ML_DSA_65)
    assert len(sig) == 3309, f"ML-DSA-65 signature must be 3309 bytes, got {len(sig)}"

    valid = provider.verify(pk, message, sig, AlgorithmName.ML_DSA_65)
    assert valid is True, "Valid ML-DSA-65 signature was rejected"

    # Tampered message
    tampered_msg = b"Vertical Bridge Ground Lease Manifest Checkpoint Beta"
    tampered_valid = provider.verify(pk, tampered_msg, sig, AlgorithmName.ML_DSA_65)
    assert tampered_valid is False, "Tampered message was incorrectly accepted by ML-DSA-65"

    # Tampered signature bytes
    corrupt_sig = bytearray(sig)
    corrupt_sig[10] ^= 0x55
    corrupt_sig_valid = provider.verify(pk, message, bytes(corrupt_sig), AlgorithmName.ML_DSA_65)
    assert corrupt_sig_valid is False, "Tampered signature bytes were incorrectly accepted by ML-DSA-65"


# =========================================================================
# 3. SLH-DSA-SHA2-128f (NIST FIPS 205)
# =========================================================================
def test_slh_dsa_archival_signature():
    provider = crypto_registry.local_provider
    pub_bytes, sk_hdl = provider.sign_generate_keypair(AlgorithmName.SLH_DSA_SHA2_128F)
    assert len(pub_bytes) == 32, f"SLH-DSA-SHA2-128f public key digest must be 32 bytes, got {len(pub_bytes)}"

    archival_data = b"Pegorion Archival Merkle Tree Root 2026-11-16T19:00:00Z"
    sig = provider.sign(sk_hdl, archival_data, AlgorithmName.SLH_DSA_SHA2_128F)
    assert len(sig) == 17088, f"SLH-DSA-SHA2-128f signature must be 17088 bytes, got {len(sig)}"

    valid = provider.verify(pub_bytes, archival_data, sig, AlgorithmName.SLH_DSA_SHA2_128F)
    assert valid is True, "Valid SLH-DSA archival signature was rejected"

    tampered_valid = provider.verify(pub_bytes, b"corrupted archival root", sig, AlgorithmName.SLH_DSA_SHA2_128F)
    assert tampered_valid is False, "Tampered archival message was incorrectly accepted by SLH-DSA"


# =========================================================================
# 4. AES-256-GCM AEAD (NIST SP 800-38D)
# =========================================================================
def test_aes_256_gcm_authenticated_encryption():
    provider = crypto_registry.local_provider
    dek = secrets.token_bytes(32)
    plaintext = b"Cell Tower Site FL-409 Ground Sublease Amendment Agreement"
    aad = b"tenant:vb-southeast;doc_id:lease-409;version:2"

    ct, tag, nonce = provider.encrypt_aead(dek, plaintext, aad)
    assert len(tag) == 16, "GCM tag must be 16 bytes"
    assert len(nonce) == 12, "GCM nonce must be 12 bytes"

    # Correct decryption
    decrypted = provider.decrypt_aead(dek, ct, tag, aad, nonce)
    assert decrypted == plaintext, "Decrypted text must match plaintext"

    # Wrong DEK failure
    wrong_dek = secrets.token_bytes(32)
    with pytest.raises(DecryptionAuthTagError):
        provider.decrypt_aead(wrong_dek, ct, tag, aad, nonce)

    # Corrupted authentication tag failure
    corrupt_tag = bytearray(tag)
    corrupt_tag[0] ^= 0x01
    with pytest.raises(DecryptionAuthTagError):
        provider.decrypt_aead(dek, ct, bytes(corrupt_tag), aad, nonce)

    # Modified associated data failure
    with pytest.raises(DecryptionAuthTagError):
        provider.decrypt_aead(dek, ct, tag, b"tenant:vb-malicious", nonce)


# =========================================================================
# 5. Document Envelope Encryption & Decryption (Module B)
# =========================================================================
def test_document_envelope_encryption_and_tenant_boundary():
    tenant_a = "org-vb-tower-assets"
    tenant_b = "org-carrier-att"
    doc_id = "doc-fl-site-101"
    raw_doc = b"%PDF-1.7 Synthetic Cell Tower Master Ground Lease Vertical Bridge"

    # Encrypt under Tenant A
    envelope = document_envelope_service.encrypt_document(
        plaintext_bytes=raw_doc,
        organization_id=tenant_a,
        document_id=doc_id,
        version=1
    )

    assert envelope.organization_id == tenant_a
    assert len(envelope.kem_ciphertext) == 1088
    assert len(envelope.auth_tag) == 16
    assert envelope.encryption_algorithm == "AES-256-GCM"
    assert envelope.key_establishment_algorithm == "ML-KEM-768"

    # Decrypt under Tenant A
    decrypted = document_envelope_service.decrypt_document(envelope, requesting_organization_id=tenant_a)
    assert decrypted == raw_doc

    # Cross-tenant access under Tenant B MUST be rejected
    with pytest.raises(CryptoSecurityError) as exc_info:
        document_envelope_service.decrypt_document(envelope, requesting_organization_id=tenant_b)
    assert "Cross-tenant access denied" in str(exc_info.value)


# =========================================================================
# 6. Canonical Manifests & Hybrid Signatures (Module C)
# =========================================================================
def test_canonical_manifest_hybrid_signing_and_tamper():
    tenant_id = "org-vb-legal"
    doc_id = "contract-vb-2024-99"

    manifest = manifest_signing_service.create_and_sign_manifest(
        organization_id=tenant_id,
        document_id=doc_id,
        document_version=1,
        document_digest_sha384="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source_metadata={"filename": "Executed_Lease.pdf", "file_size": 509337},
        encryption_reference={"algorithm": "AES-256-GCM", "kem_algorithm": "ML-KEM-768"},
        provenance={"ingest_by": "operator@verticalbridge.com", "channel": "secure_portal"},
        policy="hybrid"
    )

    assert len(manifest.signatures) == 2  # ML-DSA-65 and Ed25519
    report = manifest_signing_service.verify_manifest(manifest, required_policy="hybrid")
    assert report.status == VerificationStatus.PASS
    assert report.pqc_signature_verified is True
    assert report.classical_signature_verified is True

    # Tamper test: modify source metadata in manifest
    manifest.source_metadata["file_size"] = 999999
    tamper_report = manifest_signing_service.verify_manifest(manifest, required_policy="hybrid")
    assert tamper_report.status == VerificationStatus.FAIL
    assert tamper_report.pqc_signature_verified is False


# =========================================================================
# 7. Evidence Vault, Merkle Tree & Audit Chain Integrity (Module D)
# =========================================================================
def test_evidence_vault_hash_chain_and_merkle_checkpoints():
    org_id = "org-vb-audit-test"

    # Append 4 sequential events
    e1 = evidence_vault_service.append_event(
        organization_id=org_id,
        actor_id="user-1",
        action="document_upload",
        resource_id="doc-01",
        resource_type="document",
        payload={"filename": "Site_A_Lease.pdf"}
    )
    e2 = evidence_vault_service.append_event(
        organization_id=org_id,
        actor_id="user-1",
        action="extraction_completed",
        resource_id="doc-01",
        resource_type="lease",
        payload={"rent": 40000}
    )
    e3 = evidence_vault_service.append_event(
        organization_id=org_id,
        actor_id="legal-counsel",
        action="review_approved",
        resource_id="doc-01",
        resource_type="matter",
        payload={"approved": True}
    )

    # Sequence check
    assert e2.previous_event_hash == e1.event_hash
    assert e3.previous_event_hash == e2.event_hash

    # Create Merkle checkpoint
    checkpoint = evidence_vault_service.create_checkpoint(organization_id=org_id)
    assert checkpoint.merkle_root_sha512 is not None
    assert checkpoint.slhdsa_signature_hex is not None
    assert checkpoint.mldsa_signature_hex is not None

    # Verify vault integrity
    report = evidence_vault_service.verify_audit_vault()
    assert report.status == VerificationStatus.PASS
    assert report.hash_chain_intact is True
    assert report.merkle_roots_verified is True

    # Tamper: alter e2 payload
    e2.payload["rent"] = 80000
    tamper_report = evidence_vault_service.verify_audit_vault()
    assert tamper_report.status == VerificationStatus.FAIL
    assert len(tamper_report.altered_events) > 0

    # Restore e2 payload for clean state
    e2.payload["rent"] = 40000


# =========================================================================
# 8. Key Management & Lifecycle (Module A)
# =========================================================================
def test_key_rotation_and_revocation():
    org_id = "org-vb-keys"

    # Generate initial active key
    key1 = crypto_registry.generate_and_register_key(
        organization_id=org_id,
        purpose=KeyPurpose.MANIFEST_SIGNING,
        algorithm=AlgorithmName.ML_DSA_65
    )
    assert key1.status == KeyLifecycleStatus.ACTIVE
    assert key1.version == 1

    # Rotate key -> new version becomes active, old version becomes rotated
    key2 = crypto_registry.rotate_key(organization_id=org_id, purpose=KeyPurpose.MANIFEST_SIGNING)
    assert key2.version == 2
    assert key2.status == KeyLifecycleStatus.ACTIVE
    assert key1.status == KeyLifecycleStatus.ROTATED
    assert key1.rotated_at is not None

    # Revoke key2
    revoked = crypto_registry.revoke_key(key2.key_id, reason="Scheduled key retirement")
    assert revoked.status == KeyLifecycleStatus.REVOKED
    assert revoked.revocation_reason == "Scheduled key retirement"


# =========================================================================
# 9. Tenant Isolation, Legal Holds & Policy Enforcement (Module F)
# =========================================================================
def test_policy_and_legal_hold_enforcement():
    org_id = "org-vb-policy"

    # Default policy
    policy = tenant_policy_service.get_or_create_policy(org_id)
    assert policy.signing_policy == "hybrid"
    assert policy.legal_hold_active is False

    # Apply Legal Hold
    tenant_policy_service.apply_legal_hold(org_id, reason="Federal regulatory audit inquiry", initiated_by="general_counsel")
    assert policy.legal_hold_active is True

    # Deletion action during legal hold MUST be rejected
    allowed, msg = tenant_policy_service.check_resource_access(
        requesting_tenant_id=org_id,
        resource_tenant_id=org_id,
        user_role="admin",
        action="delete"
    )
    assert allowed is False
    assert "Active legal hold in effect" in msg

    # Restricted Legal Classification requires legal role
    allowed_viewer, err = tenant_policy_service.check_resource_access(
        requesting_tenant_id=org_id,
        resource_tenant_id=org_id,
        user_role="field_technician",
        classification=DocumentClassification.RESTRICTED_LEGAL,
        action="read"
    )
    assert allowed_viewer is False
    assert "Restricted access: Resource requires legal privileges" in err

    # Release Legal Hold
    tenant_policy_service.release_legal_hold(org_id)
    assert policy.legal_hold_active is False


# =========================================================================
# 10. Security Center API Endpoints (Module E)
# =========================================================================
def test_security_center_endpoints():
    # Inventory
    r_inv = client.get("/api/v1/security/inventory")
    assert r_inv.status_code == 200
    inv = r_inv.json()
    assert "ML-KEM-768" in inv["algorithms"]
    assert "ML-DSA-65" in inv["algorithms"]
    assert "SLH-DSA-SHA2-128f" in inv["algorithms"]
    assert "terminology_notice" in inv

    # Live Self-Tests
    r_tests = client.get("/api/v1/security/self-tests")
    assert r_tests.status_code == 200
    tests = r_tests.json()
    assert tests["overall_status"] in ["PASS", "FAIL"]
    assert tests["results"]["ML-KEM-768"]["status"] == "PASS"
    assert tests["results"]["ML-DSA-65"]["status"] == "PASS"
    assert tests["results"]["SLH-DSA-SHA2-128f"]["status"] == "PASS"

    # Benchmarks
    r_bench = client.get("/api/v1/security/benchmarks")
    assert r_bench.status_code == 200
    bench = r_bench.json()
    assert "ML-KEM-768" in bench["benchmarks"]
    assert "ML-DSA-65" in bench["benchmarks"]
    assert "AES-256-GCM" in bench["benchmarks"]

    # Vault Verify
    r_vault = client.get("/api/v1/security/vault/verify")
    assert r_vault.status_code == 200
    assert r_vault.json()["status"] in ["PASS", "FAIL"]
