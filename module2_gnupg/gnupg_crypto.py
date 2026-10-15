"""
GnuPG / OpenPGP Secret Key Cryptography Engine
=============================================
Implements RFC 4880 compliant OpenPGP encryption and decryption:
1. Asymmetric Secret Key Decryption:
   - Recipient generates an OpenPGP Key Pair (Public Key + Secret/Private Key).
   - Sender encrypts data using Recipient's Public Key.
   - Recipient decrypts data using their passphrase-protected Secret Key.
2. Symmetric Secret Key Decryption (S2K Passphrase-derived cipher):
   - Encrypts and decrypts directly with a shared secret key/passphrase.
3. Dual-mode support:
   - Uses PGPy (pure-Python OpenPGP implementation, standard RFC 4880 compliant)
   - Integrates with system `gpg` binary via python-gnupg when available
"""

import os
import shutil
from typing import Tuple, Optional

import pgpy
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm
)

try:
    import gnupg
    HAS_GNUPG_CLI = shutil.which("gpg") is not None
except ImportError:
    HAS_GNUPG_CLI = False


class OpenPGPSecretKeyEngine:
    """
    OpenPGP Engine handling Secret Key Decryption and Key Management.
    """
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def generate_keypair(self, name: str, email: str, passphrase: str) -> Tuple[pgpy.PGPKey, pgpy.PGPKey]:
        """
        Generate an OpenPGP primary secret key and subkey for encryption.
        Returns (secret_key, public_key).
        """
        # Primary key for signing/certifying
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, self.key_size)
        uid = pgpy.PGPUID.new(name, email=email)
        
        # Add user identity with standard cryptographic preferences
        key.add_uid(
            uid,
            usage={KeyFlags.Sign, KeyFlags.Certify, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed]
        )

        # Protect the secret key with passphrase
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        
        # Extract public key
        pubkey = key.pubkey
        return key, pubkey

    def encrypt_asymmetric(self, plaintext: str, recipient_pubkey: pgpy.PGPKey) -> str:
        """
        Encrypt plaintext message using recipient's Public Key.
        Returns ASCII-armored PGP message string.
        """
        message = pgpy.PGPMessage.new(plaintext)
        encrypted_message = recipient_pubkey.encrypt(message)
        return str(encrypted_message)

    def decrypt_asymmetric(self, armored_ciphertext: str, secret_key: pgpy.PGPKey, passphrase: str) -> str:
        """
        Decrypt PGP ciphertext using the recipient's Secret Key unlocked with passphrase.
        """
        message = pgpy.PGPMessage.from_blob(armored_ciphertext)
        
        # Unlock secret key with passphrase
        if secret_key.is_protected:
            with secret_key.unlock(passphrase):
                decrypted = secret_key.decrypt(message)
        else:
            decrypted = secret_key.decrypt(message)

        return str(decrypted.message)

    def encrypt_symmetric(self, plaintext: str, secret_passphrase: str) -> str:
        """
        Symmetric secret-key encryption (equivalent to 'gpg --symmetric').
        Uses AES-256 with S2K passphrase derivation.
        """
        message = pgpy.PGPMessage.new(plaintext)
        encrypted = message.encrypt(
            secret_passphrase,
            cipher=SymmetricKeyAlgorithm.AES256,
            hash=HashAlgorithm.SHA256
        )
        return str(encrypted)

    def decrypt_symmetric(self, armored_ciphertext: str, secret_passphrase: str) -> str:
        """
        Symmetric secret-key decryption (equivalent to 'gpg --decrypt').
        """
        message = pgpy.PGPMessage.from_blob(armored_ciphertext)
        decrypted = message.decrypt(secret_passphrase)
        return str(decrypted.message)

    def export_key(self, key: pgpy.PGPKey, file_path: str):
        """Export ASCII-armored public or secret key to disk."""
        with open(file_path, "w") as f:
            f.write(str(key))

    def import_key(self, file_path: str) -> pgpy.PGPKey:
        """Load ASCII-armored key from disk."""
        key, _ = pgpy.PGPKey.from_file(file_path)
        return key
