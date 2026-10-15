"""
One-Time Pad (OTP) Demonstration & Perfect Secrecy Runner
========================================================
Demonstrates:
1. Generation of cryptographically secure random key
2. Vernam encryption & bitwise XOR transformation
3. Accurate decryption back to original plaintext
4. Failure modes: Decrypting with wrong key produces uncorrelated noise
5. Two-Time Pad vulnerability demonstration (crib-dragging risk)
6. Shannon's perfect secrecy proof & equiprobable candidate analysis
"""

import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from otp_engine import OneTimePadEngine
from perfect_secrecy_analysis import (
    shannon_entropy,
    demonstrate_shannon_equiprobable_plaintexts,
    explain_perfect_secrecy
)


def run_otp_demo():
    print("=" * 70)
    print("🎲 MODULE 3: ONE-TIME PAD (OTP) & PERFECT SECRECY DEMO")
    print("=" * 70)

    # 1. Encryption and Decryption
    plaintext = "CONFIDENTIAL: Operation Blackout scheduled for 0300 UTC."
    print(f"\n[*] Original Plaintext:\n    \"{plaintext}\"")
    print(f"[*] Length: {len(plaintext)} characters ({len(plaintext.encode('utf-8'))} bytes)")

    # Generate Key and Encrypt
    ciphertext, key = OneTimePadEngine.encrypt_text(plaintext)
    
    print("\n[*] Generated Cryptographically Secure Key (Hex):")
    print(f"    {key.hex().upper()}")
    print(f"    Key Shannon Entropy: {shannon_entropy(key):.3f} bits/byte (Ideal: 8.000)")

    print("\n[*] Resulting Ciphertext (Hex):")
    print(f"    {ciphertext.hex().upper()}")
    print(f"    Ciphertext Shannon Entropy: {shannon_entropy(ciphertext):.3f} bits/byte")

    # Decrypt with genuine key
    print("\n[*] Decrypting using genuine One-Time Key...")
    decrypted_text = OneTimePadEngine.decrypt_text(ciphertext, key)
    print(f"    [+] Decrypted Result:\n    \"{decrypted_text}\"")
    assert decrypted_text == plaintext, "Decryption failed to match original plaintext!"
    print("    ✅ Decryption Verification: PASSED")

    # Decrypt with an incorrect key (Simulating attacker guessing)
    print("\n[*] Decryption Attempt with an incorrect/random key:")
    wrong_key = OneTimePadEngine.generate_key(len(key))
    bogus_decrypted = OneTimePadEngine.decrypt_bytes(ciphertext, wrong_key)
    print(f"    Decrypted Output (raw bytes): {bogus_decrypted[:30]}...")
    print("    [+] Result: Complete uncorrelated random noise (Zero leaked structure)")

    # 2. Two-Time Pad Catastrophe Demonstration
    print("\n--- Two-Time Pad (Key Reuse) Vulnerability Demonstration ---")
    msg1 = b"ATTACK AT DAWN ON SOUTHERN BORDER"
    msg2 = b"DEFEND THE HILL AT ALL EXPENSES!!"
    shared_key = OneTimePadEngine.generate_key(len(msg1))

    c1 = OneTimePadEngine.encrypt_bytes(msg1, shared_key)
    c2 = OneTimePadEngine.encrypt_bytes(msg2, shared_key)

    leaked_xor = OneTimePadEngine.two_time_pad_leak(c1, c2)
    print(f"[*] Message 1: {msg1.decode('ascii')}")
    print(f"[*] Message 2: {msg2.decode('ascii')}")
    print(f"[*] Attacker intercepts C1 and C2, then calculates C1 ⊕ C2:")
    print(f"    Leaked XOR (Hex): {leaked_xor.hex()[:40]}...")
    print("    Notice: The secret key K has cancelled out completely! (P1 ⊕ K ⊕ P2 ⊕ K = P1 ⊕ P2)")
    print("    If an attacker guesses any word in P1 (e.g. 'ATTACK'), crib-dragging")
    print("    immediately reveals the corresponding word in P2 ('DEFEND')!")

    # 3. Shannon's Equiprobable Plaintexts
    print("\n")
    demonstrate_shannon_equiprobable_plaintexts()

    # 4. Theoretical Explanation
    print("\n" + explain_perfect_secrecy())


if __name__ == "__main__":
    run_otp_demo()
