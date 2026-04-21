"""
rsa_module.py — Génération et usage de clés RSA-2048
=====================================================
Implémentation from scratch (Miller-Rabin, exponentiation rapide, CRT)
pour la gestion des clés dans le coffre-fort VaultGCSE2.
"""

import os
import random
import struct

# ─── UTILITAIRES ARITHMÉTIQUES ────────────────────────────────────────────────

def mod_pow(base: int, exp: int, mod: int) -> int:
    """Exponentiation modulaire rapide (square-and-multiply)."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int):
    """Retourne (gcd, x, y) tels que a*x + b*y = gcd."""
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def mod_inverse(a: int, m: int) -> int:
    """Inverse modulaire de a mod m (algorithme d'Euclide étendu)."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} n'a pas d'inverse mod {m}")
    return x % m

# ─── TEST DE PRIMALITÉ MILLER-RABIN ──────────────────────────────────────────

def is_prime_miller_rabin(n: int, k: int = 20) -> bool:
    """Test de primalité probabiliste Miller-Rabin avec k témoins."""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    # Écrire n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Génère un nombre premier de `bits` bits."""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # Forcer MSB=1 et impair
        if is_prime_miller_rabin(n):
            return n

# ─── GÉNÉRATION DE CLÉS RSA-2048 ─────────────────────────────────────────────

def generate_rsa_keypair(bits: int = 2048):
    """
    Génère une paire de clés RSA.
    Retourne (n, e, d) — clé publique (n, e), clé privée (n, d).
    """
    half = bits // 2
    e = 65537  # Exposant public standard

    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break

    d = mod_inverse(e, phi)
    return n, e, d

# ─── CHIFFREMENT / DÉCHIFFREMENT RSA (OAEP simplifié — padding simple) ───────
# NOTE : Pour un vrai système, utilisez OAEP. Ici on utilise un padding minimaliste
# conforme à l'esprit du projet pédagogique.

def _i2osp(x: int, length: int) -> bytes:
    """Entier vers octet-string de longueur fixe (Big Endian)."""
    return x.to_bytes(length, byteorder='big')

def _os2ip(x: bytes) -> int:
    """Octet-string vers entier (Big Endian)."""
    return int.from_bytes(x, byteorder='big')

def rsa_encrypt(message: bytes, n: int, e: int) -> bytes:
    """
    Chiffre `message` avec la clé publique (n, e).
    message doit tenir dans un entier < n.
    """
    key_len = (n.bit_length() + 7) // 8  # en octets
    if len(message) > key_len - 11:
        raise ValueError("Message trop long pour RSA avec ce n")
    # Padding PKCS#1 v1.5 simplifié
    pad_len = key_len - len(message) - 3
    padding = bytes([0x00, 0x02]) + os.urandom(pad_len).replace(b'\x00', b'\x01') + bytes([0x00])
    padded = padding + message
    m = _os2ip(padded)
    c = mod_pow(m, e, n)
    return _i2osp(c, key_len)

def rsa_decrypt(ciphertext: bytes, n: int, d: int) -> bytes:
    """Déchiffre `ciphertext` avec la clé privée (n, d)."""
    key_len = (n.bit_length() + 7) // 8
    c = _os2ip(ciphertext)
    m = mod_pow(c, d, n)
    padded = _i2osp(m, key_len)
    # Enlever le padding PKCS#1 v1.5
    if padded[0:2] != bytes([0x00, 0x02]):
        raise ValueError("Padding RSA invalide — mauvaise clé privée ?")
    sep = padded.index(0x00, 2)
    return padded[sep+1:]

# ─── SÉRIALISATION SIMPLE DES CLÉS ───────────────────────────────────────────

def save_keys(n: int, e: int, d: int, pub_path: str = "public.key", priv_path: str = "private.key"):
    """Sauvegarde les clés sous forme de fichiers binaires."""
    def _write(path, *nums):
        with open(path, 'wb') as f:
            for x in nums:
                raw = x.to_bytes((x.bit_length() + 7) // 8, 'big')
                f.write(struct.pack('>I', len(raw)))
                f.write(raw)

    _write(pub_path, n, e)
    _write(priv_path, n, d)
    print(f"[RSA] Clé publique  → {pub_path}")
    print(f"[RSA] Clé privée    → {priv_path}")

def load_keys(pub_path: str = None, priv_path: str = None):
    """Charge les clés depuis les fichiers."""
    def _read(path):
        nums = []
        with open(path, 'rb') as f:
            while True:
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                length = struct.unpack('>I', length_bytes)[0]
                nums.append(int.from_bytes(f.read(length), 'big'))
        return nums

    pub = _read(pub_path) if pub_path else None
    priv = _read(priv_path) if priv_path else None
    return pub, priv
