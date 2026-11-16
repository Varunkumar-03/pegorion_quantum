"""Provider-independent cryptographic interface and abstractions.

Defines the contract for cryptographic operations:
- Key Generation & Management
- Key Encapsulation (ML-KEM-768)
- Digital Signatures (ML-DSA-65, SLH-DSA, Ed25519)
- Authenticated Symmetric Encryption (AES-256-GCM)
- Hash Computations (SHA-384, SHA-512)
- Provider Self-Tests & Capability Diagnostics
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List
from .algorithms import AlgorithmName, VerificationStatus, KeyPurpose, KeyLifecycleStatus


class CryptoSecurityError(Exception):
    """Base exception for all cryptographic failures."""
    pass


class DecryptionAuthTagError(CryptoSecurityError):
    """Raised when authentication tag verification fails."""
    pass


class SignatureVerificationError(CryptoSecurityError):
    """Raised when digital signature verification fails."""
    pass


class KeyNotFoundError(CryptoSecurityError):
    """Raised when a key identifier or version cannot be located."""
    pass


class TamperedDataError(CryptoSecurityError):
    """Raised when an integrity check or hash verification detects tampering."""
    pass


@dataclass
class KeyRecord:
    key_id: str
    organization_id: str
    algorithm: str
    purpose: KeyPurpose
    version: int
    created_at: datetime
    status: KeyLifecycleStatus
    public_key_bytes: bytes
    key_metadata: Dict[str, Any] = field(default_factory=dict)
    rotated_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None


@dataclass
class SelfTestResult:
    algorithm: str
    status: VerificationStatus
    passed: bool
    latency_ms: float
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderInfo:
    provider_name: str
    is_available: bool
    provider_type: str  # local_development, cloud_kms, hsm, openssl_provider
    version: str
    supported_algorithms: List[str]
    status: VerificationStatus
    notes: str


class CryptoProviderBase(ABC):
    """Abstract base class for provider-independent cryptographic engines."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the provider is fully operational on this runtime."""
        pass

    @abstractmethod
    def get_info(self) -> ProviderInfo:
        """Returns provider diagnostics, active library versions, and supported algorithms."""
        pass

    @abstractmethod
    def run_self_tests(self) -> Dict[str, SelfTestResult]:
        """Runs live cryptographic self-tests and returns real runtime results."""
        pass

    # --- KEM Key Encapsulation (NIST FIPS 203) ---
    @abstractmethod
    def kem_generate_keypair(self) -> Tuple[bytes, str]:
        """Generates ML-KEM-768 public key bytes and returns (public_key_bytes, private_key_handle).
        The private key is stored securely in the provider handle store; never exported as plaintext.
        """
        pass

    @abstractmethod
    def kem_encapsulate(self, public_key_bytes: bytes) -> Tuple[bytes, bytes]:
        """Performs ML-KEM-768 encapsulation. Returns (ciphertext, shared_secret_32_bytes)."""
        pass

    @abstractmethod
    def kem_decapsulate(self, private_key_handle: str, ciphertext: bytes) -> bytes:
        """Performs ML-KEM-768 decapsulation with private key handle. Returns shared_secret_32_bytes."""
        pass

    # --- Digital Signatures (NIST FIPS 204, FIPS 205, RFC 8032) ---
    @abstractmethod
    def sign_generate_keypair(self, algorithm: AlgorithmName) -> Tuple[bytes, str]:
        """Generates signing keypair for ML-DSA-65, SLH-DSA, or Ed25519.
        Returns (public_key_bytes, private_key_handle).
        """
        pass

    @abstractmethod
    def sign(self, private_key_handle: str, message: bytes, algorithm: AlgorithmName) -> bytes:
        """Signs message with private key handle using requested algorithm."""
        pass

    @abstractmethod
    def verify(self, public_key_bytes: bytes, message: bytes, signature: bytes, algorithm: AlgorithmName) -> bool:
        """Verifies digital signature over message with public key bytes."""
        pass

    # --- Authenticated Encryption (AES-256-GCM NIST SP 800-38D) ---
    @abstractmethod
    def encrypt_aead(
        self,
        dek: bytes,
        plaintext: bytes,
        associated_data: bytes,
        nonce: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypts plaintext with AES-256-GCM.
        Returns (ciphertext, 16_byte_auth_tag, 12_byte_unique_nonce).
        """
        pass

    @abstractmethod
    def decrypt_aead(
        self,
        dek: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: bytes,
        nonce: bytes
    ) -> bytes:
        """Decrypts ciphertext with AES-256-GCM.
        Validates authentication tag before releasing decrypted bytes.
        Raises DecryptionAuthTagError if tag does not match.
        """
        pass

    # --- Cryptographic Hashes (FIPS 180-4) ---
    @abstractmethod
    def compute_digest(self, data: bytes, algorithm: AlgorithmName = AlgorithmName.SHA_384) -> bytes:
        """Computes cryptographic digest using SHA-384 or SHA-512."""
        pass
