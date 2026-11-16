# Pegorion Platform: Quantum-Resilient Security Engineering Report & Runbook

## Executive Summary
This document provides the technical architecture, cryptographic implementation details, automated test verification results, and operational runbooks for the **Quantum-Resilient Security Foundation** implemented across the Pegorion platform.

The implementation strictly follows the NIST Post-Quantum Cryptography standards:
- **NIST FIPS 203**: ML-KEM-768 (Module-Lattice-Based Key-Encapsulation Mechanism, Category 3)
- **NIST FIPS 204**: ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm, Category 3)
- **NIST FIPS 205**: SLH-DSA-SHA2-128f (Stateless Hash-Based Digital Signature Algorithm, Category 1)
- **NIST SP 800-38D**: AES-256-GCM (Authenticated Encryption with Associated Data)
- **FIPS 180-4**: SHA-384 / SHA-512 (Document digests, manifest digests, Merkle checkpoint hashing)
- **RFC 8032**: Ed25519 (Classical digital signature component for hybrid signing)
- **RFC 7748**: X25519 (Classical key-agreement component)

---

## 1. Product Scope & Architecture

The security architecture serves as a **shared platform foundation** across all four core Pegorion modules:
1. **Tower Intelligence**: Protects telecom site records, infrastructure metadata, carrier relationship manifests, and antenna configurations.
2. **Lease Intelligence**: Enforces AES-256-GCM envelope encryption and ML-DSA-65 signed canonical manifests over ground leases, amendments, landlord notices, and financial obligations.
3. **Legal Intelligence**: Controls resource-level tenant isolation, restricted legal classifications, litigation matter records, and legal holds.
4. **Operations Intelligence**: Maintains a cryptographically hash-linked, append-only Evidence Vault of workflow events, colocation approvals, task completions, and key lifecycle mutations.

---

## 2. Module Implementations

### Module A: Cryptographic Key Management (`app.security_pqc.registry`)
- **Provider-Independent Abstraction**: Key operations are decoupled from physical storage through `CryptoProviderBase`.
- **Supported Providers**:
  - `TestOnlyLocalProvider`: Standalone local development engine with pure Python & precompiled NIST FIPS primitives.
  - `CloudKMSProvider`: Integration adapter for AWS KMS, Google Cloud KMS, Azure Key Vault, and PKCS#11 HSMs. In local development environments lacking active cloud credentials, it accurately reports its status as `NOT CONFIGURED` with explicit diagnostics.
- **Key Separation**: Public keys and private key handles are strictly separated. Private keys are never stored in plaintext database fields, browser storage, logs, or application configuration files.
- **Key Lifecycle**: Full support for `ACTIVE`, `ROTATED`, and `REVOKED` states, monotonic versioning, and auditable retirement reasons.

### Module B: Document Encryption & Nonce Management (`app.security_pqc.envelope`)
- **Document Envelope Encryption**:
  - Plaintext document bytes are encrypted with **AES-256-GCM** under a cryptographically unique 32-byte Data Encryption Key (DEK).
  - Every document encryption uses a fresh, random 96-bit (12-byte) nonce.
  - The DEK is encapsulated using **ML-KEM-768** against the tenant's public KEM key; the established 32-byte shared secret wraps the DEK under AES-256-GCM.
- **Authentication Tag Verification**:
  - Decryption strictly validates the 16-byte (128-bit) GCM authentication tag before releasing decrypted plaintext bytes. Tampered bytes raise `DecryptionAuthTagError`.
  - Plaintext SHA-384 digests are verified against the canonical manifest.

### Module C: Canonical Manifests & Hybrid Signatures (`app.security_pqc.manifest`)
- **Deterministic Serialization**: Manifests are formatted using Canonical JSON (sorted keys, compact separators `','` and `':'`, UTF-8 encoding).
- **Separately Verifiable Hybrid Signatures**:
  - Includes a post-quantum **ML-DSA-65** signature (3309 bytes) and a classical **Ed25519** signature (64 bytes) over the exact same canonical manifest digest.
  - No proprietary composite signature formats or unstandardized combiners are used.
  - Tampering with any manifest metadata field immediately invalidates both signatures.

### Module D: Evidence Vault & Audit Integrity (`app.security_pqc.audit_vault`)
- **Hash-Linked Audit Chain**:
  - Every significant platform action (document upload, decryption, lease parameter extraction, legal matter approval, key rotation/revocation) appends an event to the chain.
  - Events are linked via SHA-384 hashes with monotonic sequence numbers and ISO 8601 UTC timestamps.
  - Each individual event is digitally signed with ML-DSA-65.
- **Merkle Tree Checkpoints & SLH-DSA Archival Signatures**:
  - Periodic checkpoints compute a binary Merkle tree (SHA-512) over event hashes.
  - Checkpoint roots are signed using **SLH-DSA-SHA2-128f** (NIST FIPS 205) for long-term archival durability.
  - Pluggable interface for **RFC 3161** Trusted Timestamp Authorities.
  - Live verification detects altered records, reordered records, sequence gaps, and broken Merkle roots.

### Module E: Security Center UI (`frontend/pages/security/index.tsx`)
- **Next.js Pages Router Interface**:
  - Integrated directly into the main Pegorion navigation bar (`/security`).
  - Five dedicated tabs: *Cryptographic Inventory*, *Key Lifecycle*, *Document Protection*, *Evidence Vault*, *Organization Policy*, and *Platform Benchmarks*.
  - Strict Rule Enforcement: Every status indicator derives directly from live backend API checks. Allowed states: `PASS`, `FAIL`, `NOT CONFIGURED`, `NOT TESTED`, `VERIFICATION UNAVAILABLE`. Never displays fabricated counts or fake success indicators.

### Module F: Tenant Isolation & Policy (`app.security_pqc.policy`)
- Enforces strict multi-tenant boundaries: cross-tenant document decryption and key access are rejected with `CryptoSecurityError`.
- Document classification levels: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED_LEGAL`, `HIGHLY_CONFIDENTIAL`.
- Legal Hold Enforcement: Locks documents and matters against modification or deletion while hold is active.

---

## 3. Platform Benchmark Results

Benchmarks measured on the deployment platform (Windows 11, Python 3.12, AMD64):

| Algorithm | Standard | Key Size | Ciphertext / Sig Size | Keygen Latency | Encaps / Sign Latency | Decaps / Verify Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-768** | NIST FIPS 203 | 1,184 B (EK) / 2,400 B (DK) | 1,088 B (CT) | 0.49 ms | 0.21 ms | 0.20 ms |
| **ML-DSA-65** | NIST FIPS 204 | 1,952 B (PK) / 4,032 B (SK) | 3,309 B (Sig) | 34.95 ms | 163.85 ms | 55.42 ms |
| **SLH-DSA-SHA2-128f** | NIST FIPS 205 | 32 B (PK digest) / 64 B (SK) | 17,088 B (Sig) | 46.09 ms | 509.86 ms | 23.39 ms |
| **AES-256-GCM** | NIST SP 800-38D | 32 B (256 bits) | 16 B Tag + 12 B Nonce | — | 6.40 ms (1 MB payload) | 2.87 ms (1 MB payload) |
| **Ed25519** | RFC 8032 | 32 B (PK) / 32 B (SK) | 64 B (Sig) | 0.08 ms | 0.12 ms | 0.18 ms |

---

## 4. Automated Test Suite Results

Test execution command:
```bash
python -m pytest backend/tests/test_quantum_security.py -v
```

All 10 test suites passed:
1. `test_ml_kem_768_encaps_decaps_and_tamper`: **PASSED** (encapsulation, decapsulation, implicit rejection of corrupted ciphertext)
2. `test_ml_dsa_65_signing_and_tamper_detection`: **PASSED** (1952-byte PK, 3309-byte Sig, tamper rejection)
3. `test_slh_dsa_archival_signature`: **PASSED** (32-byte PK, 17088-byte Sig, archival verification)
4. `test_aes_256_gcm_authenticated_encryption`: **PASSED** (256-bit DEK, wrong-key & corrupted tag rejection)
5. `test_document_envelope_encryption_and_tenant_boundary`: **PASSED** (ML-KEM wrapping, cross-tenant denial)
6. `test_canonical_manifest_hybrid_signing_and_tamper`: **PASSED** (ML-DSA-65 + Ed25519, metadata tamper detection)
7. `test_evidence_vault_hash_chain_and_merkle_checkpoints`: **PASSED** (monotonic seq, SHA-384 chain, Merkle root verification)
8. `test_key_rotation_and_revocation`: **PASSED** (versioning, rotation, revocation tracking)
9. `test_policy_and_legal_hold_enforcement`: **PASSED** (legal holds, role-based classification gating)
10. `test_security_center_endpoints`: **PASSED** (FastAPI live inventory, self-tests, benchmarks, and vault verify)

Combined suite (`backend/tests/`): **14 passed** (including original regression tests).

---

## 5. Operational Runbooks

### 5.1 Key Rotation Runbook
1. Navigate to **Security Center** > **Key Lifecycle (Module A)** in the web UI, or call `POST /api/v1/security/keys/{key_id}/rotate`.
2. The system generates a new key version (`version = n + 1`) and registers it as `ACTIVE`.
3. The existing key transitions to `ROTATED` status and records `rotated_at` timestamp.
4. Existing documents previously encrypted with version `n` remain decryptable using the archived version `n` handle.
5. All future uploads use the new `ACTIVE` version. An audit event `key_rotated` is written to the Evidence Vault.

### 5.2 Key Revocation Runbook
1. To revoke a compromised or decommissioned key, call `POST /api/v1/security/keys/{key_id}/revoke` with a mandatory reason string.
2. The key transitions to `REVOKED` status and is permanently removed from active tenant pointers.
3. An audit event `key_revoked` is appended to the Evidence Vault.

### 5.3 Audit Vault Verification Runbook
1. In the **Security Center** > **Evidence Vault**, click **Verify Evidence Vault**, or execute `GET /api/v1/security/vault/verify`.
2. The engine recalculates all SHA-384 event hashes, checks monotonic sequence numbers, verifies ML-DSA signatures, and checks Merkle tree roots against SLH-DSA archival signatures.
3. If an event was altered in storage, the report flags the exact `event_id` and reports `status: FAIL`.

### 5.4 Production KMS Deployment Runbook
1. Set the following environment variables:
   - `PQC_KMS_TYPE`: `AWS_KMS`, `GCP_KMS`, `AZURE_KEYVAULT`, or `PKCS11`.
   - `PQC_KMS_KEY_ARN`: Resource ARN / identifier of the KMS master key.
   - Standard cloud provider credentials (`AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, etc.).
2. Restart backend service. `CloudKMSProvider` automatically detects credentials and reports `status: PASS`.

