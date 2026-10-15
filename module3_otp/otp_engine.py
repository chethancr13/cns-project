"""
One-Time Pad (OTP) Cryptographic Engine
======================================
Implements Vernam's One-Time Pad cipher using cryptographically secure random sources.

Mathematical Foundations:
- Let P be plaintext of length N bytes
- Let K be a truly random key of length N bytes, drawn uniformly from {0, 1}^(8N)
- Encryption: C = P ⊕ K (bitwise XOR) or C_i = (P_i + K_i) mod 256
- Decryption: P = C ⊕ K (bitwise XOR) or P_i = (C_i - K_i) mod 256
- Involution property: (P ⊕ K) ⊕ K = P ⊕ (K ⊕ K) = P ⊕ 0 = P
"""

import secrets
import os
from typing import Tuple, List


class OneTimePadEngine:
    """
    Production-grade, cryptographically secure One-Time Pad implementation.
    Uses the operating system's CSPRNG (os.urandom via Python secrets).
    """

    @staticmethod
    def generate_key(length_in_bytes: int) -> bytes:
        """
        Generate a cryptographically secure random key of exact length N.
        Each byte is uniformly distributed across [0, 255] with entropy = 8 bits/byte.
        """
        if length_in_bytes <= 0:
            raise ValueError("Key length must be greater than zero.")
        return secrets.token_bytes(length_in_bytes)

    @staticmethod
    def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
        """
        Encrypt plaintext using bitwise XOR with the one-time key.
        Precondition: len(key) == len(plaintext).
        """
        if len(plaintext) != len(key):
            raise ValueError(
                f"One-Time Pad violation: Key length ({len(key)}) must exactly match "
                f"plaintext length ({len(plaintext)})."
            )
        return bytes(p ^ k for p, k in zip(plaintext, key))

    @staticmethod
    def decrypt_bytes(ciphertext: bytes, key: bytes) -> bytes:
        """
        Decrypt ciphertext using bitwise XOR with the identical one-time key.
        Precondition: len(key) == len(ciphertext).
        """
        if len(ciphertext) != len(key):
            raise ValueError(
                f"One-Time Pad violation: Key length ({len(key)}) must exactly match "
                f"ciphertext length ({len(ciphertext)})."
            )
        return bytes(c ^ k for c, k in zip(ciphertext, key))

    @staticmethod
    def encrypt_text(plaintext_str: str, encoding: str = "utf-8") -> Tuple[bytes, bytes]:
        """
        Convenience wrapper to encrypt a UTF-8 text string.
        Returns: (ciphertext_bytes, generated_key_bytes)
        """
        p_bytes = plaintext_str.encode(encoding)
        key = OneTimePadEngine.generate_key(len(p_bytes))
        ciphertext = OneTimePadEngine.encrypt_bytes(p_bytes, key)
        return ciphertext, key

    @staticmethod
    def decrypt_text(ciphertext: bytes, key: bytes, encoding: str = "utf-8") -> str:
        """
        Convenience wrapper to decrypt ciphertext back to a UTF-8 string.
        """
        p_bytes = OneTimePadEngine.decrypt_bytes(ciphertext, key)
        return p_bytes.decode(encoding)

    @staticmethod
    def forge_key_for_target(ciphertext: bytes, target_plaintext: bytes) -> bytes:
        """
        Demonstrates Shannon's Equivalence:
        Given ANY ciphertext C and ANY hypothetical plaintext P' of identical length,
        there exists a valid key K' = C ⊕ P' such that Decrypt(C, K') = P'.
        """
        if len(ciphertext) != len(target_plaintext):
            raise ValueError("Lengths must match.")
        return bytes(c ^ p for c, p in zip(ciphertext, target_plaintext))

    @staticmethod
    def two_time_pad_leak(c1: bytes, c2: bytes) -> bytes:
        """
        Demonstrates the fatal flaw of key reuse:
        C1 = P1 ⊕ K
        C2 = P2 ⊕ K
        C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
        The key cancels out completely, exposing the XOR combination of the plaintexts.
        """
        if len(c1) != len(c2):
            min_len = min(len(c1), len(c2))
            c1, c2 = c1[:min_len], c2[:min_len]
        return bytes(a ^ b for a, b in zip(c1, c2))
