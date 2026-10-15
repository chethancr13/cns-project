# Cryptography & Network Security (CNS) Engineering Project

A comprehensive, production-grade implementation of four foundational cybersecurity and cryptography components built in Python:

1. **Intrusion Detection System (IDS) & Vulnerability Scanner**
2. **GnuPG / OpenPGP Secret Key Decryption Techniques**
3. **One-Time Pad (OTP) Algorithm & Proof of Perfect Secrecy**
4. **Production Digital Signature System (RSA-PSS & ECDSA)**

---

## 📁 Project Architecture & File Hierarchy

```text
cns project/
├── requirements.txt                   # Project Python dependencies
├── run_all_demos.py                   # Master runner executing all 4 modules
├── README.md                          # Comprehensive documentation and project report
│
├── module1_ids/                       # Component 1: Intrusion Detection & Audit System
│   ├── ids_engine.py                  # Multi-threaded IDS sensor, port-scan detection, signature engine
│   ├── audit_scanner.py               # Vulnerability audit scanner (banner grabbing & CVE heuristics)
│   ├── test_ids_simulation.py         # Automated adversary simulation (benign, scan, web attacks)
│   └── ids_alerts.log                 # Real-time structured alert log (JSON formatted)
│
├── module2_gnupg/                     # Component 2: GnuPG Secret Key Decryption
│   ├── gnupg_crypto.py                # RFC 4880 OpenPGP engine (asymmetric private key & symmetric S2K)
│   ├── demo_gnupg.py                  # End-to-end demonstration & access control tests
│   └── test_gnupg.py                  # Automated unit test suite
│
├── module3_otp/                       # Component 3: One-Time Pad & Information Theory
│   ├── otp_engine.py                  # Cryptographically secure Vernam OTP engine (CSPRNG, bitwise XOR)
│   ├── perfect_secrecy_analysis.py    # Shannon's mathematical proof & equiprobable candidate analysis
│   ├── demo_otp.py                    # Demonstration of encryption, decryption, and key reuse flaws
│   └── test_otp.py                    # Automated unit test suite
│
└── module4_digital_signature/         # Component 4: Production Digital Signature System
    ├── digital_signature.py           # RSA-PSS (SHA-256) & ECDSA (SECP256R1) signing engines
    ├── file_signer_cli.py             # Real-world CLI utility for keygen, signing & verifying files
    ├── demo_digital_signature.py      # Working demo with tamper-detection & integrity tests
    └── test_digital_signature.py      # Automated unit test suite
```

---

## ⚡ Quick Start: Running the Entire Suite

To install dependencies and run all four modules:

```bash
# Install dependencies
python3 -m pip install -r requirements.txt

# Run the master demonstration runner
python3 run_all_demos.py
```

---

## 🔍 Module 1: Intrusion Detection System (IDS)

### Overview
The IDS implements a hybrid host/network detection sensor that combines **anomaly-based connection tracking** with **deep packet inspection (DPI) signature matching**:

1. **Sliding-Window Port Scan Detection**:
   - Maintains an in-memory sliding time window (default 3.0s) for every distinct source IP.
   - Computes the set of unique ports contacted. If `len(targeted_ports) >= threshold` (e.g., $\ge 3$ ports), triggers a `PORT_SCAN_DETECTED` alert.
2. **Signature-Based Attack Detection**:
   - Inspects incoming payloads against pre-compiled regular expression signatures:
     - **Path Traversal**: `../`, `..\`, `%2e%2e%2f`
     - **SQL Injection (SQLi)**: `' OR '1'='1`, `UNION SELECT`, `--`
     - **OS Command Injection**: `; whoami`, `| bash`, `cat /etc/shadow`
     - **Cross-Site Scripting (XSS)**: `<script>`, `onload=`, `document.cookie`
     - **Automated Scanner Fingerprints**: `Nmap`, `Nikto`, `sqlmap`
3. **Vulnerability Audit Scanner**:
   - `audit_scanner.py` provides multi-threaded TCP socket probing, service banner grabbing, protocol risk assessment (e.g., cleartext Telnet/FTP exposure), and seamless `python-nmap` integration when native Nmap is present.

### Running Module 1:
```bash
# Run the automated adversary attack simulation:
python3 module1_ids/test_ids_simulation.py

# Run the vulnerability scanner against target host:
python3 module1_ids/audit_scanner.py
```

---

## 🔐 Module 2: GnuPG Secret Key Decryption Techniques

### Overview
Implements standard RFC 4880 OpenPGP hybrid cryptography:

1. **Asymmetric Secret Key Decryption**:
   - Sender generates a symmetric session key $K_{session}$, encrypts the message $M$ using an approved symmetric cipher (AES-256), and encrypts $K_{session}$ using the recipient's OpenPGP Public Key ($RSA_{2048}$).
   - Decryption requires the recipient's **Secret (Private) Key**, protected by a passphrase. The engine unlocks the secret key with the passphrase, decrypts $K_{session}$, and decrypts $M$.
   - Verifies that unauthorized parties (Eve) or wrong passphrases fail cryptographically.
2. **Symmetric Secret Key Decryption (GnuPG S2K)**:
   - Implements String-to-Key (S2K) salted passphrase key derivation combined with AES-256 encryption (`gpg --symmetric`).

### Running Module 2:
```bash
# Run the interactive demonstration:
python3 module2_gnupg/demo_gnupg.py

# Run unit tests:
python3 -m unittest module2_gnupg/test_gnupg.py
```

---

## 🎲 Module 3: One-Time Pad (OTP) & Shannon's Perfect Secrecy

### Overview
Implements Gilbert Vernam's One-Time Pad using the operating system's Cryptographically Secure Pseudo-Random Number Generator (`secrets` / `os.urandom`).

- **Encryption**: $C = P \oplus K$
- **Decryption**: $P = C \oplus K$
- **Mathematical Invariant**: $(P \oplus K) \oplus K = P \oplus (K \oplus K) = P \oplus 0 = P$

### Why a Properly Used OTP Provides Perfect Secrecy:

#### 1. Mathematical Formulation (Claude Shannon, 1949)
A cryptosystem provides **perfect secrecy** if:
$$P(M = m \mid C = c) = P(M = m) \quad \forall m \in \mathcal{M}, c \in \mathcal{C}$$

In a valid OTP of length $N$ bits:
- The key $K$ is drawn uniformly at random: $P(K = k) = \frac{1}{2^N}$.
- For any fixed message $m$ and ciphertext $c$, there exists a **unique** key $k = m \oplus c$ that maps $m$ to $c$:
  $$P(C = c \mid M = m) = P(K = m \oplus c) = \frac{1}{2^N}$$
- Applying Bayes' Theorem:
  $$P(M = m \mid C = c) = \frac{P(C = c \mid M = m) \cdot P(M = m)}{P(C = c)}$$
  Since $P(C = c) = \sum_{m'} P(C = c \mid M = m') P(M = m') = \frac{1}{2^N} \sum_{m'} P(M = m') = \frac{1}{2^N}$, the terms cancel out:
  $$P(M = m \mid C = c) = \frac{\frac{1}{2^N} \cdot P(M = m)}{\frac{1}{2^N}} = P(M = m)$$

**Conclusion**: The observation of the ciphertext gives strictly **zero information** about the plaintext.

#### 2. Information Theory (Shannon Entropy)
- Conditional entropy: $H(M \mid C) = H(M)$
- Mutual information: $I(M; C) = H(M) - H(M \mid C) = 0$

#### 3. The Equiprobable Plaintext Property
Given an intercepted ciphertext $C$ of $L$ bytes, for **every possible plaintext** $P'$ of length $L$ (e.g. `"TRANSFER $10,000"`, `"DELETE ALL LOGS!"`, `"RETREAT AT ONCE!"`), there exists a valid key $K' = C \oplus P'$. Because all keys are equally probable ($P = \frac{1}{2^{8L}}$), an attacker with infinite computing power brute-forcing the key space simply recovers every possible English text of length $L$ with identical likelihood.

#### 4. The 4 Absolute Requirements for Perfect Secrecy:
1. **Truly Random Key**: Generated with maximum entropy ($8.0 \text{ bits/byte}$).
2. **Key Length $\ge$ Message Length**: Shannon proved that if $|\mathcal{K}| < |\mathcal{M}|$, perfect secrecy is impossible.
3. **Never Reused (Single Use)**: If $K$ is reused ($C_1 = P_1 \oplus K$, $C_2 = P_2 \oplus K$), then $C_1 \oplus C_2 = P_1 \oplus P_2$. The key vanishes, exposing the plaintexts to frequency analysis and crib-dragging.
4. **Kept Completely Secret**: Compromising the pad breaks the system entirely.

### Running Module 3:
```bash
# Run the demonstration & equiprobable plaintext experiment:
python3 module3_otp/demo_otp.py

# Run unit tests:
python3 -m unittest module3_otp/test_otp.py
```

---

## 🔏 Module 4: Real Working Digital Signature System

### Overview
A real, production-ready cryptographic digital signature system implementing:
1. **RSA-PSS with SHA-256** (RFC 8017 / PKCS #1 v2.2):
   - Uses Probabilistic Signature Scheme (PSS) padding, which provides a formal security proof in the Random Oracle Model (unlike legacy deterministic PKCS#1 v1.5 padding).
2. **ECDSA with NIST P-256 (SECP256R1) + SHA-256**:
   - Modern, high-performance elliptic curve signatures as used in TLS 1.3 and Bitcoin/Ethereum.
3. **Detached Signature & Tamper Detection**:
   - Demonstrates that modifying even a single byte in the signed document, or corrupting a single bit in the signature, causes verification to fail immediately.

### Real CLI File Signer Usage:
The module includes `file_signer_cli.py` to sign and verify real files on disk:

```bash
# 1. Generate an RSA Keypair (outputs keys_private.pem and keys_public.pem)
python3 module4_digital_signature/file_signer_cli.py keygen --algo rsa --out-prefix my_key

# 2. Sign any file on disk (creates a detached .sig file)
echo "Confidential Project Specification" > document.txt
python3 module4_digital_signature/file_signer_cli.py sign document.txt --key my_key_private.pem --sig document.txt.sig

# 3. Verify the file
python3 module4_digital_signature/file_signer_cli.py verify document.txt --sig document.txt.sig --key my_key_public.pem

# 4. Tamper test: Alter the document and re-verify (fails immediately)
echo "Tampered content" >> document.txt
python3 module4_digital_signature/file_signer_cli.py verify document.txt --sig document.txt.sig --key my_key_public.pem
```

### Running Module 4:
```bash
# Run full demonstration & tamper resilience tests:
python3 module4_digital_signature/demo_digital_signature.py

# Run unit tests:
python3 -m unittest module4_digital_signature/test_digital_signature.py
```
