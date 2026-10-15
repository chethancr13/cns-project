"""
Demonstration & Tamper Resilience of Digital Signatures
=======================================================
Demonstrates:
1. RSA-PSS (SHA-256) Signing and Verification
2. ECDSA (SECP256R1 + SHA-256) Signing and Verification
3. Tamper Detection 1: Message Modification (1 byte altered in payload)
4. Tamper Detection 2: Signature Bit-Flip (Corrupted signature)
5. Tamper Detection 3: Impostor Key Verification (Mismatched Public Key)
6. File Signing & Verification workflow on disk
"""

import os
import sys
import base64
import tempfile

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from digital_signature import (
    RSADigitalSignature,
    ECDSADigitalSignature,
    KeySerializer
)


def run_digital_signature_demo():
    print("=" * 70)
    print("🔏 MODULE 4: REAL PRODUCTION DIGITAL SIGNATURE DEMONSTRATION")
    print("=" * 70)

    # -------------------------------------------------------------
    # Part 1: RSA-PSS (SHA-256) Digital Signature
    # -------------------------------------------------------------
    print("\n--- Part 1: RSA-PSS Digital Signature Workflow ---")
    rsa_engine = RSADigitalSignature(key_size=2048)
    
    print("[*] Generating 2048-bit RSA Keypair...")
    rsa_priv, rsa_pub = rsa_engine.generate_keypair()

    original_contract = (
        b"LEGAL CONTRACT: Chethan Enterprises agrees to deliver "
        b"the CNS Security Module for $100,000 on or before Nov 30, 2026."
    )
    print(f"[*] Original Document ({len(original_contract)} bytes):\n    \"{original_contract.decode('ascii')}\"")

    print("\n[*] Signer computes SHA-256 hash and signs using Private Key (RSA-PSS)...")
    rsa_signature = RSADigitalSignature.sign(original_contract, rsa_priv)
    b64_sig = base64.b64encode(rsa_signature).decode('ascii')
    print(f"[+] Detached Signature Generated ({len(rsa_signature)} bytes / {len(rsa_signature)*8} bits):")
    print(f"    Base64: {b64_sig[:40]}...{b64_sig[-16:]}")

    # Test 1: Authentic Verification
    print("\n[*] Verification 1: Verifying genuine document with genuine Public Key...")
    is_valid = RSADigitalSignature.verify(original_contract, rsa_signature, rsa_pub)
    print(f"    Result: {'VALID (Authentic)' if is_valid else 'INVALID'}")
    assert is_valid, "FAIL: Authentic signature verification failed!"
    print("    ✅ Authentic RSA-PSS Signature Verified Successfully!")

    # Test 2: Message Tampering (Attacker changes $100,000 to $900,000)
    print("\n[*] Tamper Test 2: Attacker alters single character in document ($100,000 -> $900,000)...")
    tampered_contract = original_contract.replace(b"$100,000", b"$900,000")
    print(f"    Tampered Document:\n    \"{tampered_contract.decode('ascii')}\"")
    tamper_result = RSADigitalSignature.verify(tampered_contract, rsa_signature, rsa_pub)
    print(f"    Result: {'VALID' if tamper_result else 'REJECTED - INVALID SIGNATURE'}")
    assert not tamper_result, "FAIL: Tampered message was falsely accepted!"
    print("    ✅ Tamper Detection Verified: Document alteration successfully caught!")

    # Test 3: Signature Corruption (Bit flip in signature)
    print("\n[*] Tamper Test 3: Signature corrupted in transit (1 byte altered)...")
    corrupted_sig = bytearray(rsa_signature)
    corrupted_sig[10] ^= 0x01  # Flip 1 single bit
    corrupted_sig = bytes(corrupted_sig)
    corrupt_result = RSADigitalSignature.verify(original_contract, corrupted_sig, rsa_pub)
    print(f"    Result: {'VALID' if corrupt_result else 'REJECTED - INVALID SIGNATURE'}")
    assert not corrupt_result, "FAIL: Corrupted signature was accepted!"
    print("    ✅ Signature Integrity Verified: Bit-flipped signature rejected!")

    # Test 4: Key Impersonation (Wrong Public Key)
    print("\n[*] Tamper Test 4: Impostor generates their own key and claims to verify...")
    _, impostor_pub = rsa_engine.generate_keypair()
    impostor_result = RSADigitalSignature.verify(original_contract, rsa_signature, impostor_pub)
    print(f"    Result: {'VALID' if impostor_result else 'REJECTED - WRONG KEY'}")
    assert not impostor_result, "FAIL: Impostor key verified authentic signature!"
    print("    ✅ Non-Repudiation Verified: Mismatched public key rejected!")

    # -------------------------------------------------------------
    # Part 2: ECDSA (NIST P-256 + SHA-256) Digital Signature
    # -------------------------------------------------------------
    print("\n--- Part 2: ECDSA Elliptic Curve Digital Signature Workflow ---")
    print("[*] Generating ECDSA SECP256R1 Keypair...")
    ec_priv, ec_pub = ECDSADigitalSignature.generate_keypair()

    ec_msg = b"NETWORK_COMMAND: EXECUTE_FAILOVER_TO_BACKUP_NODE_US_EAST"
    print(f"[*] Message: \"{ec_msg.decode('ascii')}\"")

    ec_sig = ECDSADigitalSignature.sign(ec_msg, ec_priv)
    print(f"[+] ECDSA Signature Size: {len(ec_sig)} bytes (Extremely compact!)")

    ec_valid = ECDSADigitalSignature.verify(ec_msg, ec_sig, ec_pub)
    print(f"[*] Genuine Verification: {'VALID' if ec_valid else 'INVALID'}")
    assert ec_valid, "FAIL: ECDSA valid verification failed!"

    ec_tamper = ECDSADigitalSignature.verify(ec_msg + b"_MALICIOUS", ec_sig, ec_pub)
    print(f"[*] Tampered Verification: {'VALID' if ec_tamper else 'REJECTED (Invalid)'}")
    assert not ec_tamper, "FAIL: ECDSA tampered verification accepted!"
    print("    ✅ ECDSA Workflow Verified Successfully!")

    # -------------------------------------------------------------
    # Part 3: PEM File Export & Import Test on Disk
    # -------------------------------------------------------------
    print("\n--- Part 3: Real File Signing on Disk ---")
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_file = os.path.join(tmpdir, "firmware_update.bin")
        sig_file = os.path.join(tmpdir, "firmware_update.bin.sig")
        priv_pem_file = os.path.join(tmpdir, "vendor_private.pem")
        pub_pem_file = os.path.join(tmpdir, "vendor_public.pem")

        # 1. Create a binary firmware file
        with open(sample_file, "wb") as f:
            f.write(os.urandom(1024 * 64))  # 64 KB binary

        # 2. Export PEM keys
        with open(priv_pem_file, "wb") as f:
            f.write(KeySerializer.export_private_key_pem(rsa_priv))
        with open(pub_pem_file, "wb") as f:
            f.write(KeySerializer.export_public_key_pem(rsa_pub))

        # 3. Sign the binary
        with open(sample_file, "rb") as f:
            data = f.read()
        sig = RSADigitalSignature.sign(data, rsa_priv)
        with open(sig_file, "wb") as f:
            f.write(sig)

        print(f"[+] Created and signed sample file ({len(data)} bytes)")
        print(f"    Exported PEM Keys and Detached Signature ({sig_file})")

        # 4. Verify from disk
        with open(pub_pem_file, "rb") as f:
            loaded_pub = KeySerializer.load_public_key_pem(f.read())
        with open(sig_file, "rb") as f:
            loaded_sig = f.read()
        with open(sample_file, "rb") as f:
            loaded_data = f.read()

        file_verified = RSADigitalSignature.verify(loaded_data, loaded_sig, loaded_pub)
        assert file_verified, "File verification failed!"
        print("    ✅ On-Disk File Verification Succeeded!")

    print("\n" + "=" * 70)
    print("✅ MODULE 4 COMPLETE: Digital Signature system is fully operational!")
    print("=" * 70)


if __name__ == "__main__":
    run_digital_signature_demo()
