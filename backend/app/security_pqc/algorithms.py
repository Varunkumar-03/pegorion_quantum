"""Cryptographic standards, parameter sets, and status definitions.

NIST Standards Reference:
- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-768)
- NIST FIPS 204: Module-Lattice-Based Digital Signature Algorithm (ML-DSA-65)
- NIST FIPS 205: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA-SHA2-128f)
- NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (AES-256-GCM)
- FIPS 180-4: Secure Hash Standard (SHA-384, SHA-512)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 7748: Elliptic Curves for Security (X25519)

IMPORTANT TERMINOLOGY NOTE:
ML-KEM-768 and ML-DSA-65 are NIST security category 3 parameter sets.
The numbers 768 and 65 are not bit-security claims. No algorithm is unbreakable
or guaranteed secure forever.
"""

from enum import Enum
from typing import Dict, Any


class VerificationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_CONFIGURED = "NOT CONFIGURED"
    NOT_TESTED = "NOT TESTED"
    VERIFICATION_UNAVAILABLE = "VERIFICATION UNAVAILABLE"


class AlgorithmName(str, Enum):
    # Post-Quantum KEM
    ML_KEM_768 = "ML-KEM-768"
    
    # Post-Quantum Digital Signatures
    ML_DSA_65 = "ML-DSA-65"
    SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128f"
    
    # Classical Authenticated Encryption
    AES_256_GCM = "AES-256-GCM"
    
    # Secure Hashes
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"
    
    # Classical Asymmetric
    ED25519 = "Ed25519"
    X25519 = "X25519"


class KeyPurpose(str, Enum):
    KEM_ENVELOPE = "kem_envelope"
    DOCUMENT_DEK = "document_dek"
    MANIFEST_SIGNING = "manifest_signing"
    AUDIT_SIGNING = "audit_signing"
    ARCHIVAL_SIGNING = "archival_signing"
    HYBRID_CLASSICAL_SIGNING = "hybrid_classical_signing"


class KeyLifecycleStatus(str, Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    RETIRED = "retired"


ALGORITHM_METADATA: Dict[str, Dict[str, Any]] = {
    AlgorithmName.ML_KEM_768.value: {
        "standard": "NIST FIPS 203",
        "category": "Post-Quantum Key Establishment (KEM)",
        "security_level": "NIST Category 3",
        "description": "Module-Lattice-Based Key-Encapsulation Mechanism for establishing shared key material.",
        "public_key_bytes": 1184,
        "ciphertext_bytes": 1088,
        "shared_secret_bytes": 32,
        "purpose": "Shared key establishment for document envelope encryption; does not directly encrypt PDFs.",
        "note": "Parameter set 768 corresponds to NIST Category 3, not a 768-bit security claim."
    },
    AlgorithmName.ML_DSA_65.value: {
        "standard": "NIST FIPS 204",
        "category": "Post-Quantum Digital Signature",
        "security_level": "NIST Category 3",
        "description": "Module-Lattice-Based Digital Signature Algorithm.",
        "public_key_bytes": 1952,
        "secret_key_bytes": 4032,
        "signature_bytes": 3309,
        "purpose": "Post-quantum signatures for manifests, reports, and audit checkpoints.",
        "note": "Parameter set 65 corresponds to NIST Category 3, not a 65-bit security claim."
    },
    AlgorithmName.SLH_DSA_SHA2_128F.value: {
        "standard": "NIST FIPS 205",
        "category": "Stateless Hash-Based Digital Signature",
        "security_level": "NIST Category 1 (Parameter set SHA2-128f)",
        "description": "Stateless hash-based signature scheme providing conservative quantum resistance.",
        "public_key_bytes": 32,
        "secret_key_bytes": 64,
        "signature_bytes": 17088,
        "purpose": "Archival signing for long-term audit checkpoints and evidence vault verification.",
        "note": "Selected parameter set is SLH-DSA-SHA2-128f for archival durability."
    },
    AlgorithmName.AES_256_GCM.value: {
        "standard": "NIST SP 800-38D",
        "category": "Authenticated Encryption with Associated Data (AEAD)",
        "security_level": "256-bit symmetric security",
        "description": "Galois/Counter Mode authenticated encryption.",
        "key_bytes": 32,
        "nonce_bytes": 12,
        "tag_bytes": 16,
        "purpose": "Authenticated encryption of document bytes with unique DEK and safe 96-bit nonces.",
        "note": "Requires unique nonce per document encryption and strict tag verification before release."
    },
    AlgorithmName.SHA_384.value: {
        "standard": "NIST FIPS 180-4",
        "category": "Cryptographic Hash Function",
        "security_level": "384-bit output length",
        "description": "SHA-2 family cryptographic hash function.",
        "digest_bytes": 48,
        "purpose": "Canonical document digests, manifest integrity, and audit record linkage."
    },
    AlgorithmName.SHA_512.value: {
        "standard": "NIST FIPS 180-4",
        "category": "Cryptographic Hash Function",
        "security_level": "512-bit output length",
        "description": "SHA-2 family cryptographic hash function.",
        "digest_bytes": 64,
        "purpose": "Merkle tree checkpoint generation and evidence vault root hashing."
    },
    AlgorithmName.ED25519.value: {
        "standard": "RFC 8032",
        "category": "Classical Digital Signature",
        "security_level": "128-bit classical security",
        "description": "Edwards-curve Digital Signature Algorithm over Curve25519.",
        "public_key_bytes": 32,
        "signature_bytes": 64,
        "purpose": "Classical component of hybrid digital signatures for backward-compatible verification."
    },
    AlgorithmName.X25519.value: {
        "standard": "RFC 7748",
        "category": "Classical Key Agreement",
        "security_level": "128-bit classical security",
        "description": "Diffie-Hellman function over Curve25519.",
        "public_key_bytes": 32,
        "shared_secret_bytes": 32,
        "purpose": "Classical key-agreement component where required by dual-key protocol policy."
    }
}

