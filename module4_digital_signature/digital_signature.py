"""
Production-Grade Digital Signature Implementation
==================================================
Implements industry-standard cryptographic digital signature schemes using
Python's `cryptography` library (hazmat primitives):

1. RSA-PSS with SHA-256 (RFC 8017 / PKCS #1 v2.2):
   - Probabilistic Signature Scheme (PSS)
   - Salt length = MGF1 with SHA-256
   - Superior security over legacy deterministic PKCS#1 v1.5 padding

2. ECDSA with NIST P-256 (SECP256R1) and SHA-256:
   - High-performance, compact elliptic curve signatures
   - Used extensively in TLS 1.3, SSH, and modern identity systems

Guarantees:
- Authenticity: Confirms identity of the signer (possessor of private key)
- Integrity: Guarantees the document has not been altered in transit
- Non-Repudiation: Signer cannot deny having signed the document
"""

import base64
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


class RSADigitalSignature:
    """
    RSA-PSS Digital Signature Engine.
    Uses SHA-256 hash and Probabilistic Signature Scheme (PSS) padding.
    """
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def generate_keypair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate a secure RSA keypair with public exponent e=65537."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Sign arbitrary data bytes using RSA-PSS with SHA-256.
        Returns the raw signature bytes.
        """
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """
        Verify the signature against the data using the public key.
        Returns True if authentic and untampered, False otherwise.
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


class ECDSADigitalSignature:
    """
    ECDSA (Elliptic Curve Digital Signature Algorithm) Engine.
    Uses NIST Curve SECP256R1 (P-256) and SHA-256.
    """
    @staticmethod
    def generate_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate an ECDSA keypair on the SECP256R1 curve."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign(data: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Sign data using ECDSA with SHA-256."""
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify ECDSA signature with SHA-256."""
        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


# PEM Serialization Utilities
class KeySerializer:
    """Handles serialization and deserialization of cryptographic keys in PEM format."""

    @staticmethod
    def export_private_key_pem(private_key, password: Optional[str] = None) -> bytes:
        """Serialize private key to PKCS#8 PEM format."""
        if password:
            enc = serialization.BestAvailableEncryption(password.encode('utf-8'))
        else:
            enc = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        )

    @staticmethod
    def export_public_key_pem(public_key) -> bytes:
        """Serialize public key to SubjectPublicKeyInfo PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_private_key_pem(pem_bytes: bytes, password: Optional[str] = None):
        """Load private key from PEM bytes."""
        pwd_bytes = password.encode('utf-8') if password else None
        return serialization.load_pem_private_key(pem_bytes, password=pwd_bytes)

    @staticmethod
    def load_public_key_pem(pem_bytes: bytes):
        """Load public key from PEM bytes."""
        return serialization.load_pem_public_key(pem_bytes)
