"""
Production File Signing & Verification CLI Utility
===================================================
A real-world tool to generate cryptographic keys, sign documents/code/binaries,
and verify authenticity and integrity.

Usage Examples:
  # 1. Generate Keypair
  python3 file_signer_cli.py keygen --algo rsa --out-prefix my_keys

  # 2. Sign a document
  python3 file_signer_cli.py sign sample_contract.pdf --key my_keys_private.pem --sig sample_contract.pdf.sig

  # 3. Verify the document
  python3 file_signer_cli.py verify sample_contract.pdf --sig sample_contract.pdf.sig --key my_keys_public.pem
"""

import os
import sys
import argparse
import base64

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from digital_signature import (
    RSADigitalSignature,
    ECDSADigitalSignature,
    KeySerializer
)


def cmd_keygen(args):
    """Generate RSA or ECDSA keypair and save to PEM files."""
    algo = args.algo.lower()
    prefix = args.out_prefix

    priv_path = f"{prefix}_private.pem"
    pub_path = f"{prefix}_public.pem"

    if algo == "rsa":
        engine = RSADigitalSignature(key_size=args.bits)
        priv_key, pub_key = engine.generate_keypair()
    elif algo == "ecdsa":
        priv_key, pub_key = ECDSADigitalSignature.generate_keypair()
    else:
        print(f"[-] Unsupported algorithm: {algo}")
        sys.exit(1)

    priv_pem = KeySerializer.export_private_key_pem(priv_key, password=args.password)
    pub_pem = KeySerializer.export_public_key_pem(pub_key)

    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    print(f"[+] Successfully generated {algo.upper()} keypair:")
    print(f"    Private Key: {priv_path}")
    print(f"    Public Key:  {pub_path}")


def cmd_sign(args):
    """Sign an input file and output detached signature."""
    if not os.path.exists(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)
    if not os.path.exists(args.key):
        print(f"[-] Private key not found: {args.key}")
        sys.exit(1)

    with open(args.file, "rb") as f:
        file_bytes = f.read()

    with open(args.key, "rb") as f:
        priv_pem = f.read()

    priv_key = KeySerializer.load_private_key_pem(priv_pem, password=args.password)

    # Check key type (RSA or EC)
    if hasattr(priv_key, "private_numbers"):
        # RSA Key
        sig_bytes = RSADigitalSignature.sign(file_bytes, priv_key)
        algo_name = "RSA-PSS (SHA-256)"
    else:
        # EC Key
        sig_bytes = ECDSADigitalSignature.sign(file_bytes, priv_key)
        algo_name = "ECDSA-P256 (SHA-256)"

    out_sig_path = args.sig or (args.file + ".sig")
    with open(out_sig_path, "wb") as f:
        f.write(sig_bytes)

    b64_sig = base64.b64encode(sig_bytes).decode('ascii')
    print(f"[+] Successfully signed file with {algo_name}:")
    print(f"    File:           {args.file} ({len(file_bytes)} bytes)")
    print(f"    Signature File: {out_sig_path}")
    print(f"    Signature B64:  {b64_sig[:32]}... ({len(sig_bytes)} bytes)")


def cmd_verify(args):
    """Verify detached signature of a file."""
    if not os.path.exists(args.file):
        print(f"[-] Target file not found: {args.file}")
        sys.exit(1)
    if not os.path.exists(args.sig):
        print(f"[-] Signature file not found: {args.sig}")
        sys.exit(1)
    if not os.path.exists(args.key):
        print(f"[-] Public key file not found: {args.key}")
        sys.exit(1)

    with open(args.file, "rb") as f:
        file_bytes = f.read()

    with open(args.sig, "rb") as f:
        sig_bytes = f.read()

    with open(args.key, "rb") as f:
        pub_pem = f.read()

    pub_key = KeySerializer.load_public_key_pem(pub_pem)

    if hasattr(pub_key, "public_numbers"):
        # RSA
        is_valid = RSADigitalSignature.verify(file_bytes, sig_bytes, pub_key)
        algo = "RSA-PSS"
    else:
        # ECDSA
        is_valid = ECDSADigitalSignature.verify(file_bytes, sig_bytes, pub_key)
        algo = "ECDSA-P256"

    print("\n" + "=" * 60)
    print("DIGITAL SIGNATURE VERIFICATION REPORT")
    print("=" * 60)
    print(f"File:      {args.file}")
    print(f"Algorithm: {algo} with SHA-256")
    print(f"Status:    {'VALID - AUTHENTIC & UNTAMPERED' if is_valid else 'INVALID - TAMPERED OR FORGED'}")
    print("=" * 60)

    if is_valid:
        print("[+] SUCCESS: Digital signature is cryptographically VALID!")
        sys.exit(0)
    else:
        print("[-] FAILED: Signature is INVALID! Document has been altered or signed with a different key.")
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description="Cryptographic File Signer & Verifier CLI")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Keygen
    kp = subparsers.add_parser("keygen", help="Generate public/private keypair")
    kp.add_argument("--algo", choices=["rsa", "ecdsa"], default="rsa", help="Signature algorithm")
    kp.add_argument("--bits", type=int, default=2048, help="RSA key size in bits")
    kp.add_argument("--out-prefix", default="key", help="Prefix for key files")
    kp.add_argument("--password", default=None, help="Optional private key password")
    kp.set_defaults(func=cmd_keygen)

    # Sign
    sp = subparsers.add_parser("sign", help="Sign a file")
    sp.add_argument("file", help="File to sign")
    sp.add_argument("--key", required=True, help="Private key PEM file")
    sp.add_argument("--sig", default=None, help="Output signature file (.sig)")
    sp.add_argument("--password", default=None, help="Private key password if protected")
    sp.set_defaults(func=cmd_sign)

    # Verify
    vp = subparsers.add_parser("verify", help="Verify a file's signature")
    vp.add_argument("file", help="Original file")
    vp.add_argument("--sig", required=True, help="Signature file (.sig)")
    vp.add_argument("--key", required=True, help="Public key PEM file")
    vp.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
