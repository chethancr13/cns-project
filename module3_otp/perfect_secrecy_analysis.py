"""
Information-Theoretic Proof & Analysis of Perfect Secrecy
=========================================================
Claude Shannon's Mathematical Foundation (1949):
"Communication Theory of Secrecy Systems", Bell System Technical Journal.

Core Theorem:
A cryptosystem has PERFECT SECRECY if and only if for all plaintexts m in M
and all ciphertexts c in C:
    P(M = m | C = c) = P(M = m)

Equivalently in terms of Shannon Entropy:
    H(M | C) = H(M)   and   I(M; C) = 0
(The mutual information between the plaintext and ciphertext is strictly zero).
"""

import math
from collections import Counter
from typing import Dict, List
from otp_engine import OneTimePadEngine


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy in bits per byte (max 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def demonstrate_shannon_equiprobable_plaintexts():
    """
    Empirical demonstration of Shannon's theorem:
    Shows that given a single ciphertext, EVERY plausible plaintext of the same
    length corresponds to an equally likely random key.
    """
    original_msg = b"TRANSFER $10,000"
    real_key = OneTimePadEngine.generate_key(len(original_msg))
    ciphertext = OneTimePadEngine.encrypt_bytes(original_msg, real_key)

    # Candidate hypothetical plaintexts of identical length (16 bytes)
    candidates = [
        b"TRANSFER $10,000",  # True plaintext
        b"TRANSFER $99,999",  # Fraudulent transfer
        b"DELETE ALL LOGS!",  # Sabotage command
        b"RETREAT AT ONCE!",  # Military command
        b"CANCEL CONTRACT!",  # Commercial order
    ]

    print("=" * 70)
    print("🧠 SHANNON'S PERFECT SECRECY: EQUIPROBABLE CANDIDATE DECRYPTION")
    print("=" * 70)
    print(f"Intercepted Ciphertext (Hex): {ciphertext.hex().upper()}")
    print(f"Message Length: {len(ciphertext)} bytes ({len(ciphertext)*8} bits)")
    print(f"Key Space Size: 2^{len(ciphertext)*8} = 2^128 possible keys\n")
    print("An eavesdropper with INFINITE computing power tests candidate keys:")
    print("-" * 70)

    for cand in candidates:
        # Compute the unique key that would decrypt ciphertext to this candidate
        hypothetical_key = OneTimePadEngine.forge_key_for_target(ciphertext, cand)
        # Verify decryption
        decrypted = OneTimePadEngine.decrypt_bytes(ciphertext, hypothetical_key)
        
        # Check entropy of this hypothetical key
        ent = shannon_entropy(hypothetical_key)
        
        print(f"Key (Hex): {hypothetical_key.hex()[:24]}... | Decrypted: \"{decrypted.decode('ascii')}\"")

    print("-" * 70)
    print(
        "CONCLUSION: Because every candidate key is uniformly random with "
        "exact probability 1 / 2^128, the eavesdropper has ZERO mathematical basis "
        "to distinguish the true message from any other valid text of that length."
    )


def explain_perfect_secrecy() -> str:
    """Return theoretical and mathematical explanation text."""
    explanation = """
================================================================================
EXPLANATION: WHY A PROPERLY USED ONE-TIME PAD PROVIDES PERFECT SECRECY
================================================================================

1. MATHEMATICAL FORMULATION (SHANNON'S THEOREM, 1949):
   Let:
     - M be the random variable over the plaintext space M.
     - C be the random variable over the ciphertext space C.
     - K be the random variable over the key space K.

   In OTP, each key bit k_i is generated independently and uniformly:
     P(K = k) = 1 / |K| = 1 / 2^N

   The conditional probability that ciphertext C = c given message M = m is:
     P(C = c | M = m) = P(M ⊕ K = c | M = m)
                      = P(K = m ⊕ c)
                      = 1 / 2^N

   Using Bayes' Theorem to compute the posterior probability:
     P(M = m | C = c) = [ P(C = c | M = m) * P(M = m) ] / P(C = c)

   Where the marginal probability of ciphertext is:
     P(C = c) = Σ_{m'} P(C = c | M = m') * P(M = m')
              = Σ_{m'} (1 / 2^N) * P(M = m')
              = (1 / 2^N) * Σ_{m'} P(M = m')
              = 1 / 2^N * 1 = 1 / 2^N

   Substituting back:
     P(M = m | C = c) = [ (1 / 2^N) * P(M = m) ] / (1 / 2^N)
                      = P(M = m)

   Result: P(M = m | C = c) = P(M = m)
   The probability distribution of the plaintext after observing the ciphertext
   is IDENTICAL to the prior probability distribution before observing it.
   Observing the ciphertext reveals strictly ZERO information about the plaintext.

2. INFORMATION THEORY PERSPECTIVE (ENTROPY):
   - Shannon Entropy of message: H(M)
   - Conditional Entropy given ciphertext: H(M | C) = H(M)
   - Mutual Information: I(M; C) = H(M) - H(M | C) = 0.
   No physical or mathematical measurement can reduce uncertainty.

3. THE 4 ABSOLUTE REQUIREMENTS FOR PERFECT SECRECY:
   1) Truly Random Key: Keys must be generated from true physical randomness
      or cryptographically secure entropy, with maximum entropy (8 bits/byte).
   2) Key Length >= Message Length: Shannon proved that if |K| < |M|,
      perfect secrecy is mathematically impossible.
   3) Used Exactly Once (Never Reused):
      If key K is used twice (C1 = P1 ⊕ K, C2 = P2 ⊕ K):
        C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
      The key is completely eliminated! Natural language redundancy (letter
      frequencies, spaces) allows an attacker to extract both plaintexts
      via crib-dragging.
   4) Kept Absolutely Secret: Both sender and receiver must protect the pad.
================================================================================
"""
    return explanation


if __name__ == "__main__":
    print(explain_perfect_secrecy())
    demonstrate_shannon_equiprobable_plaintexts()
