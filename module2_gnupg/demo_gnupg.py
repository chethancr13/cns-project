"""
Demonstration of OpenPGP / GnuPG Secret Key Decryption Techniques
================================================================
Demonstrates:
1. OpenPGP Keypair Generation (Public Key + Passphrase-protected Secret Key)
2. Asymmetric Secret Key Decryption (Recipient Private Key + Passphrase)
3. Cryptographic Access Control: Verification that missing or wrong secret keys fail
4. Symmetric Secret Key Decryption (Passphrase-derived AES-256)
"""

import os
import sys
import tempfile

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from gnupg_crypto import OpenPGPSecretKeyEngine


def run_gnupg_demo():
    print("=" * 70)
    print("🔐 MODULE 2: GNUPG SECRET KEY DECRYPTION DEMONSTRATION")
    print("=" * 70)

    engine = OpenPGPSecretKeyEngine(key_size=2048)
    
    # -------------------------------------------------------------
    # 1. Asymmetric Secret Key Decryption Workflow
    # -------------------------------------------------------------
    print("\n--- Part 1: Asymmetric OpenPGP Secret Key Decryption ---")
    bob_passphrase = "BobSecretPassphrase2026!"
    alice_passphrase = "AlicePassphrase999!"

    print("[*] Generating OpenPGP Keypair for Recipient (Bob)...")
    bob_sec_key, bob_pub_key = engine.generate_keypair(
        name="Bob NetworkSec",
        email="bob@cns-security.org",
        passphrase=bob_passphrase
    )
    print(f"    [+] Bob's Key ID: {bob_pub_key.fingerprint}")
    print(f"    [+] Bob's Secret Key Protected: {bob_sec_key.is_protected}")

    print("\n[*] Generating OpenPGP Keypair for Unrelated Party (Alice)...")
    alice_sec_key, alice_pub_key = engine.generate_keypair(
        name="Alice Analyst",
        email="alice@cns-security.org",
        passphrase=alice_passphrase
    )

    confidential_message = (
        "CONFIDENTIAL TOP SECRET DOCUMENT: Network Gateway Access Keys: "
        "SSH-Key: 9f8a8b1c4e2d3f4a; Firewall Bypasses Disabled; IDS Audit Mode Active."
    )
    print(f"\n[*] Original Plaintext:\n    \"{confidential_message}\"")

    # Alice encrypts the message for Bob using Bob's Public Key
    print("\n[*] Sender (Alice) encrypts message using Bob's OpenPGP Public Key...")
    pgp_ciphertext = engine.encrypt_asymmetric(confidential_message, bob_pub_key)
    
    print("\n[+] Resulting OpenPGP ASCII-Armored Ciphertext (sample):")
    lines = pgp_ciphertext.strip().split("\n")
    print("\n".join(lines[:4] + ["    ... (encrypted binary packets) ..."] + lines[-2:]))

    # Test 1: Adversary without Bob's Secret Key tries to decrypt
    print("\n[*] Attack Simulation 1: Alice (or Adversary) attempts decryption using Alice's Secret Key...")
    try:
        engine.decrypt_asymmetric(pgp_ciphertext, alice_sec_key, alice_passphrase)
        print("    [-] ERROR: Unauthorized party decrypted ciphertext!")
    except Exception as e:
        print(f"    [+] ACCESS DENIED (Expected): Decryption failed without Bob's secret key: {type(e).__name__}")

    # Test 2: Attempting decryption with Bob's Secret Key but WRONG Passphrase
    print("\n[*] Attack Simulation 2: Adversary possesses Bob's secret key file but enters WRONG passphrase...")
    try:
        engine.decrypt_asymmetric(pgp_ciphertext, bob_sec_key, "WrongPassword123!")
        print("    [-] ERROR: Key was unlocked with wrong passphrase!")
    except Exception as e:
        print(f"    [+] ACCESS DENIED (Expected): Passphrase verification failed: {type(e).__name__}")

    # Test 3: Authorized Bob decrypts with his Secret Key & Passphrase
    print("\n[*] Authorized Operation: Bob unlocks Secret Key with valid passphrase and decrypts...")
    decrypted_text = engine.decrypt_asymmetric(pgp_ciphertext, bob_sec_key, bob_passphrase)
    print(f"    [+] Decrypted Plaintext:\n    \"{decrypted_text}\"")

    assert decrypted_text == confidential_message, "Decrypted message does not match original plaintext!"
    print("\n    ✅ Asymmetric Secret Key Decryption Verified Successfully!")

    # -------------------------------------------------------------
    # 2. Symmetric Secret Key Decryption Workflow
    # -------------------------------------------------------------
    print("\n--- Part 2: Symmetric Secret Key Decryption (GnuPG S2K) ---")
    shared_secret = "CNS-Project-Shared-Secret-Key-7788"
    secret_payload = "Database connection string: postgres://root:dbpass@192.168.1.50:5432/core"

    print(f"[*] Plaintext: \"{secret_payload}\"")
    print(f"[*] Encrypting symmetrically with secret key / passphrase...")
    sym_ciphertext = engine.encrypt_symmetric(secret_payload, shared_secret)

    print("\n[*] Attempting symmetric decryption with incorrect secret key...")
    try:
        engine.decrypt_symmetric(sym_ciphertext, "InvalidSecretKey404")
        print("    [-] ERROR: Decrypted with invalid secret key!")
    except Exception as e:
        print(f"    [+] DECRYPTION REJECTED (Expected): {type(e).__name__}")

    print("\n[*] Decrypting symmetrically with valid secret key...")
    sym_decrypted = engine.decrypt_symmetric(sym_ciphertext, shared_secret)
    print(f"    [+] Successfully Decrypted: \"{sym_decrypted}\"")

    assert sym_decrypted == secret_payload, "Symmetric decryption failed match!"
    print("\n    ✅ Symmetric Secret Key Decryption Verified Successfully!")

    print("\n" + "=" * 70)
    print("✅ MODULE 2 COMPLETE: GnuPG Secret Key Decryption fully operational!")
    print("=" * 70)


if __name__ == "__main__":
    run_gnupg_demo()
