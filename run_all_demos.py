"""
Master Project Demonstration & Verification Runner
===================================================
Executes all 4 components of the Cryptography & Network Security (CNS) Project:
1. Module 1: Intrusion Detection System (IDS) & Vulnerability Scanner
2. Module 2: GnuPG Secret Key Decryption (Asymmetric & Symmetric S2K)
3. Module 3: One-Time Pad (OTP) & Shannon's Perfect Secrecy
4. Module 4: Production-Grade Digital Signatures (RSA-PSS & ECDSA)
"""

import os
import sys
import time

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, "module1_ids"))
sys.path.insert(0, os.path.join(current_dir, "module2_gnupg"))
sys.path.insert(0, os.path.join(current_dir, "module3_otp"))
sys.path.insert(0, os.path.join(current_dir, "module4_digital_signature"))

from test_ids_simulation import run_ids_simulation
from demo_gnupg import run_gnupg_demo
from demo_otp import run_otp_demo
from demo_digital_signature import run_digital_signature_demo


def main():
    print("#" * 78)
    print("#  CRYPTOGRAPHY & NETWORK SECURITY (CNS) ENGINEERING PROJECT RUNNER  #")
    print("#" * 78)
    start_time = time.time()
    results = {}

    # Module 1
    try:
        run_ids_simulation()
        results["Module 1: Intrusion Detection System (IDS)"] = "PASSED"
    except Exception as e:
        results["Module 1: Intrusion Detection System (IDS)"] = f"FAILED: {e}"

    time.sleep(1)

    # Module 2
    try:
        run_gnupg_demo()
        results["Module 2: GnuPG Secret Key Decryption"] = "PASSED"
    except Exception as e:
        results["Module 2: GnuPG Secret Key Decryption"] = f"FAILED: {e}"

    time.sleep(1)

    # Module 3
    try:
        run_otp_demo()
        results["Module 3: One-Time Pad & Perfect Secrecy"] = "PASSED"
    except Exception as e:
        results["Module 3: One-Time Pad & Perfect Secrecy"] = f"FAILED: {e}"

    time.sleep(1)

    # Module 4
    try:
        run_digital_signature_demo()
        results["Module 4: Real Production Digital Signature"] = "PASSED"
    except Exception as e:
        results["Module 4: Real Production Digital Signature"] = f"FAILED: {e}"

    elapsed = time.time() - start_time

    # Final Summary Table
    print("\n" + "#" * 78)
    print("#                        FINAL PROJECT EXECUTION SUMMARY                     #")
    print("#" * 78)
    print(f"{'Module Name':<55} | {'Status':<18}")
    print("-" * 78)
    all_passed = True
    for mod, status in results.items():
        if status != "PASSED":
            all_passed = False
        print(f"{mod:<55} | {status:<18}")
    print("-" * 78)
    print(f"Total Execution Time: {elapsed:.2f} seconds")
    if all_passed:
        print("🎉 ALL 4 ENGINEERING MODULES COMPLETED AND VERIFIED SUCCESSFULLY!")
    else:
        print("⚠️ Some modules encountered errors. Please check logs.")
    print("#" * 78)


if __name__ == "__main__":
    main()
