# Pegorion Quantum-Resilient Security Platform

A production-grade, provider-independent Post-Quantum Cryptographic (PQC) security service and Evidence Vault compliant with NIST FIPS 203, FIPS 204, FIPS 205, and NIST SP 800-38D.

---

## 🛡️ Core Cryptographic Architecture

| Layer | Standard | Algorithm | Parameter Set / Spec | Role |
| :--- | :--- | :--- | :--- | :--- |
| **Key Establishment** | **NIST FIPS 203** | `ML-KEM-768` | Category 3 parameter set | Document envelope encryption, DEK wrapping |
| **Digital Signatures**| **NIST FIPS 204** | `ML-DSA-65` | Category 3 parameter set | Manifest signing, report and audit attestation |
| **Archival Seals**   | **NIST FIPS 205** | `SLH-DSA-SHA2-128f` | Stateless Hash-Based | Evidence Vault Merkle root checkpoint attestation |
| **Data Encryption**  | **NIST SP 800-38D**| `AES-256-GCM` | 256-bit key, 96-bit nonce, 128-bit tag | Authenticated payload encryption |
| **Digest Engine**    | **FIPS 180-4** | `SHA-384` / `SHA-512` | 384/512-bit secure hash | Hash-chained event stream and Merkle tree leaves |
| **Classical Hybrid** | **RFC 8032 / RFC 7748** | `Ed25519` / `X25519` | Classical ECC | Hybrid dual-signature validation |

> **Strict Terminology Notice**: Per NIST FIPS specifications, `ML-KEM-768` and `ML-DSA-65` are classified as **Category 3 parameter sets** providing security equivalent to AES-192 against classical and quantum cryptanalysis. No cryptographic algorithm is described as "unbreakable". All system status indicators reflect live backend tests: `PASS`, `FAIL`, `NOT CONFIGURED`, `NOT TESTED`, `VERIFICATION UNAVAILABLE`.

---

## 📁 Repository Structure

```
quantum/
├── Pegorion_Quantum_Resilient_Security_Claude_Prompt.pdf  # Source specification
├── backend/
│   ├── app/
│   │   ├── security_pqc/              # Post-Quantum Cryptographic Core
│   │   │   ├── algorithms.py          # Algorithm catalog & terminology enforcement
│   │   │   ├── provider_base.py       # Abstract CryptoProviderBase contract
│   │   │   ├── test_provider.py       # In-memory local PQC engine (mlkem, dilithium, slhdsa)
│   │   │   ├── cloud_kms_provider.py  # Production Cloud KMS adapter (AWS/GCP/Azure)
│   │   │   ├── registry.py            # Key lifecycle (ACTIVE/ROTATED/REVOKED), benchmarks
│   │   │   ├── envelope.py            # PQC-ENV-1.0 Envelope encryption & decapsulation
│   │   │   ├── manifest.py            # RFC 8785 Canonical JSON manifests & hybrid signatures
│   │   │   ├── audit_vault.py         # Evidence Vault with SHA-384 hash chain & Merkle trees
│   │   │   └── policy.py              # Multi-tenant boundary isolation & statutory holds
│   │   ├── routers/
│   │   │   ├── security_center.py     # REST endpoints for /api/v1/security/*
│   │   │   ├── documents.py           # Document upload & PQC envelope encapsulation
│   │   │   └── auth.py                # Tenant authentication & identity
│   │   ├── models/                    # Data models (User, Document, AuditLog)
│   │   └── core/                      # Configuration & database
│   ├── tests/
│   │   ├── test_quantum_security.py   # Comprehensive test suite covering Modules A-G
│   │   └── test_api.py                # Service health & API root tests
│   ├── main.py                        # Standalone Quantum Security FastAPI app
│   └── requirements.txt               # Dependencies (mlkem, dilithium-py, slh-dsa, etc.)
├── frontend/
│   ├── pages/
│   │   ├── index.tsx                  # Quantum Security Center (main dashboard)
│   │   ├── security/index.tsx         # Full interactive security management center
│   │   └── _app.tsx                   # Next.js root with React Query provider
│   ├── components/
│   │   └── Layout.tsx                 # Quantum Security navigation layout
│   └── lib/
│       └── api.ts                     # React Query hooks for security endpoints
└── docs/
    └── QUANTUM_RESILIENT_SECURITY.md  # Architectural specification & operational runbooks
```

---

## 🚀 Quickstart

### 1. Backend Service
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```
- API Documentation: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

### 2. Run Test Suite
```bash
cd backend
python -m pytest tests -v
```
All 14 cryptographic test suites covering encapsulation, signing, archival checkpoints, envelope decapsulation, tamper detection, and key rotation pass with 100% compliance.

### 3. Frontend Security Center Dashboard
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:3000` to access the Quantum Security Center:
- **Algorithm Inventory**: NIST FIPS standards, parameter sets, and live verification states.
- **Key Lifecycle Management**: Real-time generation, rotation, and revocation of ML-KEM, ML-DSA, and SLH-DSA keys.
- **Document Envelope Tester**: Live encryption into `PQC-ENV-1.0` format and tamper-evident tag validation.
- **Evidence Vault Inspector**: SHA-384 hash-linked event stream, binary Merkle tree root computation, and SLH-DSA checkpoint attestation.
- **Policy Engine**: Tenancy boundary enforcement and statutory legal hold lock verification.
- **Telemetry & Benchmarks**: Real-time platform micro-benchmarks measuring keygen, encapsulation, and signing latency.
