🔐 VaultGCSE2 — Secure Digital Vault

A hybrid cryptographic system that combines a custom AES variant (AES-ENSA) with RSA-2048 and HMAC-SHA256 to securely encrypt and protect files.

This project demonstrates practical cryptography concepts including symmetric encryption, asymmetric encryption, integrity verification, and avalanche effect testing.

📌 Features
🔑 Hybrid Encryption
AES-ENSA (custom AES-128 variant) for fast data encryption
RSA-2048 for secure key exchange
🛡️ Integrity Protection
HMAC-SHA256 ensures data authenticity and tamper detection
📦 Custom Secure File Format (.vault)
Structured encrypted container
📊 Avalanche Effect Testing
Measures cryptographic strength
⚙️ Command-Line Interface (CLI)
🏗️ Project Structure
miniprojet2crypto/
│
├── vault.py                # Main CLI application
├── aes_ensa.py            # Custom AES implementation
├── rsa_module.py          # RSA implementation (from scratch)
├── avalanche_test.py      # Avalanche effect testing
├── avalanche_results.txt  # Test results
├── trace_test.txt         # Debug/trace logs
├── rapport_technique.pdf  # Technical report
🔐 Encryption Architecture

The .vault file format:

┌──────────────────────────────────────────┐
│ Header  (256 bytes) : AES key encrypted  │
│                        with RSA          │
│ IV      (16 bytes)  : Initialization     │
│ Payload (variable)  : AES-CBC encrypted  │
│ Footer  (32 bytes) : HMAC-SHA256         │
└──────────────────────────────────────────┘
🚀 Installation
Requirements
Python 3.x
Clone or extract the project:
unzip miniprojet2crypto.zip
cd miniprojet2crypto
⚙️ Usage
1. Generate RSA Keys
python vault.py keygen
2. Encrypt a File
python vault.py encrypt file.txt --pub public.key

Output:

file.txt.vault
3. Decrypt a File
python vault.py decrypt file.txt.vault --priv private.key
🔬 AES-ENSA Customization

The AES variant uses a custom S-Box based on:

f(x) = (a * x + b) mod 256

Modify in aes_ensa.py:

MATRICULE_A = 2
MATRICULE_B = 3

⚠️ Notes:

a must be odd to ensure bijection
Values are based on student ID (matricule)
📊 Avalanche Effect Testing

Run:

python avalanche_test.py

Results are stored in:

avalanche_results.txt

This evaluates how small input changes affect output — a key property of secure cryptographic systems.

🧠 Key Concepts Demonstrated
Symmetric Encryption (AES-CBC)
Asymmetric Encryption (RSA)
Key Exchange
Message Authentication Codes (HMAC)
Secure File Design
Cryptographic Testing (Avalanche Effect)
