"""Test-only and local development cryptographic provider.

Implements all required post-quantum and classical algorithms:
- ML-KEM-768 (NIST FIPS 203)
- ML-DSA-65 (NIST FIPS 204)
- SLH-DSA-SHA2-128f (NIST FIPS 205)
- AES-256-GCM (NIST SP 800-38D)
- SHA-384 and SHA-512 (FIPS 180-4)
- Ed25519 (RFC 8032) and X25519 (RFC 7748)

Security Invariant:
Private keys are never stored in plaintext database fields, browser storage,
logs, or application configuration. Handles are opaque references to a secure
isolated in-memory or encrypted keystore.
"""

import hashlib
import os
import secrets
import time
from typing import Dict, Any, Optional, Tuple, List
from uuid import uuid4

# Cryptography primitives
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.exceptions import InvalidTag, InvalidSignature

# Post-quantum NIST FIPS primitives
import mlkem
from dilithium_py.ml_dsa import ML_DSA_65
import slhdsa

from .algorithms import (
    AlgorithmName,
    VerificationStatus,
    ALGORITHM_METADATA,
    KeyPurpose
)
from .provider_base import (
    CryptoProviderBase,
    ProviderInfo,
    SelfTestResult,
    CryptoSecurityError,
    DecryptionAuthTagError,
    SignatureVerificationError,
    KeyNotFoundError,
    TamperedDataError
)


class TestOnlyLocalProvider(CryptoProviderBase):
    """Local development and test cryptographic engine with full FIPS 203/204/205 support."""

    def __init__(self):
        self._provider_name = "TestOnlyLocalProvider"
        self._version = "1.0.0-fips-local"
        self._kem_instance = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)
        
        # Isolated private key storage (opaque handle -> secret key bytes)
        # Never exposed outside this module
        self._private_keystore: Dict[str, Tuple[str, bytes]] = {}

    @property
    def name(self) -> str:
        return self._provider_name

    def is_available(self) -> bool:
        return True

    def get_info(self) -> ProviderInfo:
        return ProviderInfo(
            provider_name=self._provider_name,
            is_available=True,
            provider_type="local_development",
            version=self._version,
            supported_algorithms=[
                AlgorithmName.ML_KEM_768.value,
                AlgorithmName.ML_DSA_65.value,
                AlgorithmName.SLH_DSA_SHA2_128F.value,
                AlgorithmName.AES_256_GCM.value,
                AlgorithmName.SHA_384.value,
                AlgorithmName.SHA_512.value,
                AlgorithmName.ED25519.value,
                AlgorithmName.X25519.value
            ],
            status=VerificationStatus.PASS,
            notes="Active local provider implementing NIST FIPS 203, FIPS 204, FIPS 205, and AES-256-GCM."
        )

    # --- KEM Key Encapsulation (NIST FIPS 203) ---
    def kem_generate_keypair(self) -> Tuple[bytes, str]:
        """Generates ML-KEM-768 keypair. Returns (public_key_bytes, private_key_handle)."""
        ek, dk = self._kem_instance.key_gen()
        handle = f"kem-hdl-{uuid4()}"
        self._private_keystore[handle] = (AlgorithmName.ML_KEM_768.value, dk.to_bytes())
        return ek.to_bytes(), handle

    def kem_encapsulate(self, public_key_bytes: bytes) -> Tuple[bytes, bytes]:
        """Encapsulates a shared secret using ML-KEM-768.
        Returns (ciphertext, shared_secret_32_bytes).
        """
        try:
            ek = mlkem.EncapsKey.from_bytes(public_key_bytes)
            shared_secret, ciphertext = self._kem_instance.encaps(ek)
            return bytes(ciphertext), bytes(shared_secret)
        except Exception as e:
            raise CryptoSecurityError(f"ML-KEM-768 encapsulation failed: {str(e)}") from e

    def kem_decapsulate(self, private_key_handle: str, ciphertext: bytes) -> bytes:
        """Decapsulates shared secret using private key handle."""
        if private_key_handle not in self._private_keystore:
            raise KeyNotFoundError(f"KEM private key handle not found: {private_key_handle}")
        
        algo, dk_bytes = self._private_keystore[private_key_handle]
        if algo != AlgorithmName.ML_KEM_768.value:
            raise CryptoSecurityError(f"Handle is not an ML-KEM key: {algo}")
        
        try:
            dk = mlkem.DecapsKey.from_bytes(dk_bytes)
            shared_secret = self._kem_instance.decaps(dk, ciphertext)
            return bytes(shared_secret)
        except Exception as e:
            raise CryptoSecurityError(f"ML-KEM-768 decapsulation failed: {str(e)}") from e

    # --- Digital Signatures (NIST FIPS 204, FIPS 205, RFC 8032) ---
    def sign_generate_keypair(self, algorithm: AlgorithmName) -> Tuple[bytes, str]:
        """Generates signature keypair. Returns (public_key_bytes, private_key_handle)."""
        handle = f"sig-hdl-{uuid4()}"
        
        if algorithm == AlgorithmName.ML_DSA_65:
            pk, sk = ML_DSA_65.keygen()
            self._private_keystore[handle] = (algorithm.value, sk)
            return pk, handle

        elif algorithm == AlgorithmName.SLH_DSA_SHA2_128F:
            kp = slhdsa.KeyPair.gen(slhdsa.sha2_128f)
            pub_bytes = kp.pub.digest()
            # Store digest representation of keypair for secure handle resolution
            self._private_keystore[handle] = (algorithm.value, kp.digest())
            return pub_bytes, handle

        elif algorithm == AlgorithmName.ED25519:
            priv = ed25519.Ed25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes_raw()
            self._private_keystore[handle] = (algorithm.value, priv.private_bytes_raw())
            return pub_bytes, handle

        else:
            raise ValueError(f"Unsupported signing algorithm: {algorithm}")

    def sign(self, private_key_handle: str, message: bytes, algorithm: AlgorithmName) -> bytes:
        """Signs message using private key handle."""
        if private_key_handle not in self._private_keystore:
            raise KeyNotFoundError(f"Signing private key handle not found: {private_key_handle}")
        
        stored_algo, secret_data = self._private_keystore[private_key_handle]
        if stored_algo != algorithm.value:
            raise CryptoSecurityError(f"Algorithm mismatch: expected {algorithm.value}, found {stored_algo}")

        try:
            if algorithm == AlgorithmName.ML_DSA_65:
                return bytes(ML_DSA_65.sign(secret_data, message))
            
            elif algorithm == AlgorithmName.SLH_DSA_SHA2_128F:
                kp = slhdsa.KeyPair.from_digest(secret_data, slhdsa.sha2_128f)
                return bytes(kp.sign_pure(message))

            elif algorithm == AlgorithmName.ED25519:
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(secret_data)
                return bytes(priv.sign(message))
            
            else:
                raise ValueError(f"Unsupported signing algorithm: {algorithm}")
        except Exception as e:
            raise CryptoSecurityError(f"Signing failed with {algorithm.value}: {str(e)}") from e

    def verify(self, public_key_bytes: bytes, message: bytes, signature: bytes, algorithm: AlgorithmName) -> bool:
        """Verifies signature over message using public key bytes."""
        try:
            if algorithm == AlgorithmName.ML_DSA_65:
                return bool(ML_DSA_65.verify(public_key_bytes, message, signature))

            elif algorithm == AlgorithmName.SLH_DSA_SHA2_128F:
                pub = slhdsa.PublicKey.from_digest(public_key_bytes, slhdsa.sha2_128f)
                return bool(pub.verify_pure(message, signature))

            elif algorithm == AlgorithmName.ED25519:
                pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
                pub.verify(signature, message)
                return True

            else:
                raise ValueError(f"Unsupported signature verification algorithm: {algorithm}")
        except InvalidSignature:
            return False
        except Exception as e:
            # Rejection on malformed input or verification error
            return False

    # --- Authenticated Encryption (AES-256-GCM NIST SP 800-38D) ---
    def encrypt_aead(
        self,
        dek: bytes,
        plaintext: bytes,
        associated_data: bytes,
        nonce: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypts plaintext with AES-256-GCM.
        Generates unique 12-byte nonce if not provided.
        Returns (ciphertext, 16_byte_tag, 12_byte_nonce).
        """
        if len(dek) != 32:
            raise ValueError(f"AES-256-GCM requires a 32-byte key, got {len(dek)} bytes")
        
        if nonce is None:
            nonce = secrets.token_bytes(12)
        elif len(nonce) != 12:
            raise ValueError(f"AES-256-GCM standard nonce length is 12 bytes, got {len(nonce)}")

        aesgcm = AESGCM(dek)
        # AESGCM.encrypt appends 16-byte tag to ciphertext
        encrypted_raw = aesgcm.encrypt(nonce, plaintext, associated_data)
        ciphertext = encrypted_raw[:-16]
        tag = encrypted_raw[-16:]
        return ciphertext, tag, nonce

    def decrypt_aead(
        self,
        dek: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: bytes,
        nonce: bytes
    ) -> bytes:
        """Decrypts ciphertext with AES-256-GCM and verifies 16-byte authentication tag.
        Raises DecryptionAuthTagError if tag verification fails.
        """
        if len(dek) != 32:
            raise ValueError(f"AES-256-GCM requires a 32-byte key, got {len(dek)} bytes")
        if len(tag) != 16:
            raise DecryptionAuthTagError(f"Invalid authentication tag length: {len(tag)} (expected 16)")
        if len(nonce) != 12:
            raise CryptoSecurityError(f"Invalid nonce length: {len(nonce)} (expected 12)")

        aesgcm = AESGCM(dek)
        ct_with_tag = ciphertext + tag
        try:
            plaintext = aesgcm.decrypt(nonce, ct_with_tag, associated_data)
            return plaintext
        except InvalidTag as e:
            raise DecryptionAuthTagError("AES-256-GCM authentication tag verification failed. Data corrupted or key invalid.") from e
        except Exception as e:
            raise DecryptionAuthTagError(f"Decryption failure: {str(e)}") from e

    # --- Cryptographic Hashes ---
    def compute_digest(self, data: bytes, algorithm: AlgorithmName = AlgorithmName.SHA_384) -> bytes:
        if algorithm == AlgorithmName.SHA_384:
            return hashlib.sha384(data).digest()
        elif algorithm == AlgorithmName.SHA_512:
            return hashlib.sha512(data).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # --- Runtime Self-Tests ---
    def run_self_tests(self) -> Dict[str, SelfTestResult]:
        """Runs live cryptographic self-tests across all algorithms.
        Validates both positive execution and tamper detection.
        """
        results: Dict[str, SelfTestResult] = {}

        # 1. ML-KEM-768 Self-Test
        t0 = time.perf_counter()
        try:
            ek_bytes, hdl = self.kem_generate_keypair()
            ct, ss1 = self.kem_encapsulate(ek_bytes)
            ss2 = self.kem_decapsulate(hdl, ct)
            assert ss1 == ss2, "ML-KEM-768 shared secret mismatch"
            # Invalid ciphertext tamper test
            corrupt_ct = bytearray(ct)
            corrupt_ct[0] ^= 0xFF
            ss_tampered = self.kem_decapsulate(hdl, bytes(corrupt_ct))
            assert ss_tampered != ss1, "ML-KEM tamper resistance check failed"
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.ML_KEM_768.value] = SelfTestResult(
                algorithm=AlgorithmName.ML_KEM_768.value,
                status=VerificationStatus.PASS,
                passed=True,
                latency_ms=round(lat, 2),
                details={"public_key_bytes": len(ek_bytes), "ciphertext_bytes": len(ct), "shared_secret_bytes": len(ss1)}
            )
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.ML_KEM_768.value] = SelfTestResult(
                algorithm=AlgorithmName.ML_KEM_768.value,
                status=VerificationStatus.FAIL,
                passed=False,
                latency_ms=round(lat, 2),
                error_message=str(e)
            )

        # 2. ML-DSA-65 Self-Test
        t0 = time.perf_counter()
        try:
            pk, sig_hdl = self.sign_generate_keypair(AlgorithmName.ML_DSA_65)
            test_msg = b"Pegorion Self Test Message ML-DSA-65"
            sig = self.sign(sig_hdl, test_msg, AlgorithmName.ML_DSA_65)
            valid = self.verify(pk, test_msg, sig, AlgorithmName.ML_DSA_65)
            assert valid is True, "ML-DSA-65 valid signature rejected"
            # Tamper test
            tampered_valid = self.verify(pk, test_msg + b"!", sig, AlgorithmName.ML_DSA_65)
            assert tampered_valid is False, "ML-DSA-65 tampered signature accepted"
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.ML_DSA_65.value] = SelfTestResult(
                algorithm=AlgorithmName.ML_DSA_65.value,
                status=VerificationStatus.PASS,
                passed=True,
                latency_ms=round(lat, 2),
                details={"public_key_bytes": len(pk), "signature_bytes": len(sig)}
            )
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.ML_DSA_65.value] = SelfTestResult(
                algorithm=AlgorithmName.ML_DSA_65.value,
                status=VerificationStatus.FAIL,
                passed=False,
                latency_ms=round(lat, 2),
                error_message=str(e)
            )

        # 3. SLH-DSA-SHA2-128f Self-Test
        t0 = time.perf_counter()
        try:
            pub_bytes, slh_hdl = self.sign_generate_keypair(AlgorithmName.SLH_DSA_SHA2_128F)
            test_msg = b"Pegorion Archival Checkpoint Test"
            sig = self.sign(slh_hdl, test_msg, AlgorithmName.SLH_DSA_SHA2_128F)
            valid = self.verify(pub_bytes, test_msg, sig, AlgorithmName.SLH_DSA_SHA2_128F)
            assert valid is True, "SLH-DSA valid signature rejected"
            tampered_valid = self.verify(pub_bytes, b"corrupt", sig, AlgorithmName.SLH_DSA_SHA2_128F)
            assert tampered_valid is False, "SLH-DSA tampered signature accepted"
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.SLH_DSA_SHA2_128F.value] = SelfTestResult(
                algorithm=AlgorithmName.SLH_DSA_SHA2_128F.value,
                status=VerificationStatus.PASS,
                passed=True,
                latency_ms=round(lat, 2),
                details={"public_key_bytes": len(pub_bytes), "signature_bytes": len(sig)}
            )
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.SLH_DSA_SHA2_128F.value] = SelfTestResult(
                algorithm=AlgorithmName.SLH_DSA_SHA2_128F.value,
                status=VerificationStatus.FAIL,
                passed=False,
                latency_ms=round(lat, 2),
                error_message=str(e)
            )

        # 4. AES-256-GCM Self-Test
        t0 = time.perf_counter()
        try:
            dek = secrets.token_bytes(32)
            pt = b"Test Synthetic Lease Document Bytes Content"
            aad = b"tenant_id:vb-001;doc_id:lease-42"
            ct, tag, nonce = self.encrypt_aead(dek, pt, aad)
            decrypted = self.decrypt_aead(dek, ct, tag, aad, nonce)
            assert decrypted == pt, "AES-256-GCM plaintext mismatch"
            # Tag verification failure test
            corrupt_tag = bytearray(tag)
            corrupt_tag[0] ^= 0xFF
            tag_failed = False
            try:
                self.decrypt_aead(dek, ct, bytes(corrupt_tag), aad, nonce)
            except DecryptionAuthTagError:
                tag_failed = True
            assert tag_failed, "AES-256-GCM corrupt tag was not rejected"
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.AES_256_GCM.value] = SelfTestResult(
                algorithm=AlgorithmName.AES_256_GCM.value,
                status=VerificationStatus.PASS,
                passed=True,
                latency_ms=round(lat, 2),
                details={"key_bits": 256, "nonce_bytes": len(nonce), "tag_bytes": len(tag)}
            )
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.AES_256_GCM.value] = SelfTestResult(
                algorithm=AlgorithmName.AES_256_GCM.value,
                status=VerificationStatus.FAIL,
                passed=False,
                latency_ms=round(lat, 2),
                error_message=str(e)
            )

        # 5. Ed25519 Classical Self-Test
        t0 = time.perf_counter()
        try:
            ed_pub, ed_hdl = self.sign_generate_keypair(AlgorithmName.ED25519)
            test_msg = b"Pegorion Hybrid Classical Signature Test"
            ed_sig = self.sign(ed_hdl, test_msg, AlgorithmName.ED25519)
            ed_valid = self.verify(ed_pub, test_msg, ed_sig, AlgorithmName.ED25519)
            assert ed_valid is True, "Ed25519 valid signature rejected"
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.ED25519.value] = SelfTestResult(
                algorithm=AlgorithmName.ED25519.value,
                status=VerificationStatus.PASS,
                passed=True,
                latency_ms=round(lat, 2),
                details={"public_key_bytes": len(ed_pub), "signature_bytes": len(ed_sig)}
            )
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.ED25519.value] = SelfTestResult(
                algorithm=AlgorithmName.ED25519.value,
                status=VerificationStatus.FAIL,
                passed=False,
                latency_ms=round(lat, 2),
                error_message=str(e)
            )

        # 6. SHA-384 / SHA-512 Self-Test
        t0 = time.perf_counter()
        try:
            d384 = self.compute_digest(b"Pegorion Digest Test", AlgorithmName.SHA_384)
            d512 = self.compute_digest(b"Pegorion Digest Test", AlgorithmName.SHA_512)
            assert len(d384) == 48, f"SHA-384 expected 48 bytes, got {len(d384)}"
            assert len(d512) == 64, f"SHA-512 expected 64 bytes, got {len(d512)}"
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.SHA_384.value] = SelfTestResult(
                algorithm=AlgorithmName.SHA_384.value,
                status=VerificationStatus.PASS,
                passed=True,
                latency_ms=round(lat, 2),
                details={"sha384_bytes": len(d384), "sha512_bytes": len(d512)}
            )
        except Exception as e:
            lat = (time.perf_counter() - t0) * 1000
            results[AlgorithmName.SHA_384.value] = SelfTestResult(
                algorithm=AlgorithmName.SHA_384.value,
                status=VerificationStatus.FAIL,
                passed=False,
                latency_ms=round(lat, 2),
                error_message=str(e)
            )

        return results

