# 🔐 Mini Crypto Project — AES-ENSA, RSA & Secure Vault

## 📌 Overview

This project is a practical implementation of fundamental cryptographic concepts, combining:

* A **custom AES-128 variant (AES-ENSA)**
* An **RSA encryption module**
* A **secure vault system for data protection**
* An **avalanche effect analysis tool**

It is designed for educational purposes to understand how modern cryptographic systems work internally.

---

## ⚙️ Features

### 🔸 1. AES-ENSA (Custom AES Variant)

* AES-128 inspired implementation
* Uses a **custom affine S-Box**:
  [
  f(x) = (a \cdot x + b) \mod 256
  ]
* Parameters `a` and `b` are derived from a student ID
* Demonstrates how substitution layers impact security

---

### 🔸 2. RSA Module

* Public/Private key generation
* Encryption & decryption functions
* Demonstrates asymmetric cryptography principles

---

### 🔸 3. Secure Vault

* Stores sensitive data securely
* Uses encryption to protect stored content
* Combines AES and RSA concepts

---

### 🔸 4. Avalanche Effect Analysis

* Measures how small input changes affect output
* Evaluates cryptographic strength
* Outputs results in:

  * `avalanche_results.txt`
  * `trace_test.txt`

---

## 📁 Project Structure

```
miniprojet2crypto/
│
├── aes_ensa.py              # Custom AES implementation
├── rsa_module.py           # RSA encryption module
├── vault.py                # Secure vault system
├── avalanche_test.py       # Avalanche effect testing
│
├── avalanche_results.txt   # Test results
├── trace_test.txt          # Execution trace
│
└── rapport_technique.pdf   # Technical report
```

---

## 🚀 How to Use

### 1️⃣ Clone the repository

```bash
git clone https://github.com/your-username/mini-crypto-project.git
cd mini-crypto-project
```

### 2️⃣ Run AES module

```bash
python aes_ensa.py
```

### 3️⃣ Run RSA module

```bash
python rsa_module.py
```

### 4️⃣ Test Avalanche Effect

```bash
python avalanche_test.py
```

---

## ⚠️ Important Configuration

Inside `aes_ensa.py`, update:

```python
MATRICULE_A = 2
MATRICULE_B = 3
```

➡️ These values must match your **student ID digits**
➡️ `a` must be **odd** to ensure a valid permutation

---

## 📊 Educational Objectives

This project helps understand:

* Symmetric encryption (AES)
* Asymmetric encryption (RSA)
* Substitution & permutation principles
* Cryptographic strength evaluation (avalanche effect)

---

## 📄 Documentation

For detailed explanations, refer to:

📘 `rapport_technique.pdf`

---

## 🛠️ Technologies Used

* Python 3
* Standard libraries only (no external dependencies)

---

## 👤 Author

* Datchi*



If you want, I can also:

* make it more **cybersecurity-professional (GitHub portfolio ready)**
* add **badges (build, license, Python version)**
* or rewrite it in **clean English for international recruiters** 🚀
