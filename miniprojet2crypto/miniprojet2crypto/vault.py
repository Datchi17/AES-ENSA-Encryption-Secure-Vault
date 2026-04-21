"""
vault.py — VaultGCSE2 : Coffre-Fort Numérique Sécurisé
=======================================================
Architecture hybride AES-ENSA + RSA-2048 + HMAC-SHA256

FORMAT DU FICHIER .vault :
┌──────────────────────────────────────────┐
│ Header  (256 octets) : clé AES chiffrée  │
│                        par RSA           │
│ IV      ( 16 octets) : vecteur init. CBC │
│ Payload (variable  ) : données chiffrées │
│                        AES-ENSA CBC      │
│ Footer  ( 32 octets) : HMAC-SHA256       │
│                        sur tout le reste │
└──────────────────────────────────────────┘

Usage CLI :
  python vault.py keygen
  python vault.py encrypt <fichier> [--pub public.key]
  python vault.py decrypt <fichier.vault> [--priv private.key]
"""

import os
import sys
import secrets
import hashlib
import hmac as hmac_lib
import struct

from aes_ensa import cbc_encrypt, cbc_decrypt
from rsa_module import (
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    save_keys, load_keys
)

# ─── CONSTANTES DE FORMAT ────────────────────────────────────────────────────

HEADER_SIZE  = 256   # octets — clé AES chiffrée par RSA
IV_SIZE      = 16    # octets
FOOTER_SIZE  = 32    # octets — HMAC-SHA256

# ─── HMAC-SHA256 (double hachage pour bonus) ──────────────────────────────────

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Calcule HMAC-SHA256 avec double hachage (bonus).
    H1 = HMAC-SHA256(key, data)
    H2 = HMAC-SHA256(key, H1 || data)   ← renforce la résistance aux attaques
    """
    h1 = hmac_lib.new(key, data, hashlib.sha256).digest()
    h2 = hmac_lib.new(key, h1 + data, hashlib.sha256).digest()
    return h2

def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
    """Vérifie le HMAC en temps constant (protection timing attacks)."""
    computed = compute_hmac(key, data)
    return hmac_lib.compare_digest(computed, expected)

# ─── CHIFFREMENT ─────────────────────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str, pub_key_path: str = "public.key"):
    """
    Chiffre un fichier quelconque.
    
    Étapes :
    1. Lire le fichier source
    2. Générer une clé AES-128 aléatoire + IV aléatoire
    3. Chiffrer les données avec AES-ENSA en mode CBC
    4. Chiffrer la clé AES avec RSA (clé publique)
    5. Calculer HMAC-SHA256 sur header+IV+payload
    6. Écrire le fichier .vault structuré
    """
    print(f"[+] Chiffrement de : {input_path}")

    # Lecture des données
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    print(f"    Taille originale : {len(plaintext)} octets")

    # Chargement de la clé publique RSA
    pub, _ = load_keys(pub_path=pub_key_path)
    n, e = pub[0], pub[1]

    # Génération clé AES et IV aléatoires
    aes_key = secrets.token_bytes(16)   # 128 bits
    iv      = secrets.token_bytes(16)   # 128 bits

    # Chiffrement des données (AES-ENSA CBC)
    print("    Chiffrement AES-ENSA CBC ...")
    payload = cbc_encrypt(plaintext, aes_key, iv)
    print(f"    Taille payload : {len(payload)} octets")

    # Chiffrement de la clé AES par RSA
    print("    Chiffrement de la clé AES par RSA ...")
    encrypted_aes_key = rsa_encrypt(aes_key, n, e)
    # Compléter/tronquer à exactement 256 octets
    if len(encrypted_aes_key) > HEADER_SIZE:
        raise ValueError(f"Clé RSA chiffrée trop grande : {len(encrypted_aes_key)} octets")
    header = encrypted_aes_key.ljust(HEADER_SIZE, b'\x00')  # padding nul si nécessaire

    # Calcul HMAC sur header + IV + payload (la clé HMAC = hash de la clé AES)
    hmac_key = hashlib.sha256(aes_key).digest()
    protected_data = header + iv + payload
    footer = compute_hmac(hmac_key, protected_data)

    # Écriture du fichier .vault
    with open(output_path, 'wb') as f:
        f.write(header)   # 256 octets
        f.write(iv)       #  16 octets
        f.write(payload)  # variable
        f.write(footer)   #  32 octets

    print(f"[✓] Fichier chiffré : {output_path}")
    print(f"    Taille totale    : {len(header)+len(iv)+len(payload)+len(footer)} octets")

# ─── DÉCHIFFREMENT ────────────────────────────────────────────────────────────

def decrypt_file(vault_path: str, output_path: str, priv_key_path: str = "private.key"):
    """
    Déchiffre un fichier .vault.
    
    Étapes :
    1. Lire le fichier .vault et extraire les sections
    2. Vérifier le HMAC (intégrité) — AVANT le déchiffrement
    3. Déchiffrer la clé AES avec la clé privée RSA
    4. Déchiffrer le payload avec AES-ENSA CBC
    5. Écrire le fichier restauré
    """
    print(f"[+] Déchiffrement de : {vault_path}")

    with open(vault_path, 'rb') as f:
        raw = f.read()

    if len(raw) < HEADER_SIZE + IV_SIZE + FOOTER_SIZE + 16:
        raise ValueError("Fichier .vault trop court — corrompu ?")

    # Extraction des sections
    header  = raw[:HEADER_SIZE]
    iv      = raw[HEADER_SIZE : HEADER_SIZE + IV_SIZE]
    footer  = raw[-FOOTER_SIZE:]
    payload = raw[HEADER_SIZE + IV_SIZE : -FOOTER_SIZE]

    print(f"    Header  : {HEADER_SIZE} octets")
    print(f"    IV      : {IV_SIZE} octets  → {iv.hex()}")
    print(f"    Payload : {len(payload)} octets")
    print(f"    Footer  : {FOOTER_SIZE} octets")

    # Chargement de la clé privée RSA
    _, priv = load_keys(priv_path=priv_key_path)
    n, d = priv[0], priv[1]

    # Déchiffrement de la clé AES
    print("    Déchiffrement de la clé AES via RSA ...")
    try:
        encrypted_aes_key = header.rstrip(b'\x00')
        aes_key = rsa_decrypt(encrypted_aes_key, n, d)
    except Exception as ex:
        raise ValueError(
            f"[✗] ÉCHEC du déchiffrement RSA — clé privée incorrecte ?\n"
            f"    Détail : {ex}"
        )

    if len(aes_key) != 16:
        raise ValueError(f"[✗] Clé AES invalide après déchiffrement RSA ({len(aes_key)} octets au lieu de 16)")

    # Vérification HMAC (intégrité)
    print("    Vérification HMAC-SHA256 (intégrité) ...")
    hmac_key = hashlib.sha256(aes_key).digest()
    protected_data = header + iv + payload
    if not verify_hmac(hmac_key, protected_data, footer):
        raise ValueError(
            "[✗] HMAC invalide — le fichier a été modifié ou la clé est incorrecte !\n"
            "    Déchiffrement interrompu pour protéger l'intégrité."
        )
    print("    [✓] HMAC valide — intégrité confirmée")

    # Déchiffrement AES-ENSA CBC
    print("    Déchiffrement AES-ENSA CBC ...")
    plaintext = cbc_decrypt(payload, aes_key, iv)

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    print(f"[✓] Fichier restauré : {output_path}  ({len(plaintext)} octets)")

# ─── GÉNÉRATION DE CLÉS ───────────────────────────────────────────────────────

def keygen(pub_path: str = "public.key", priv_path: str = "private.key"):
    """Génère une paire RSA-2048 et la sauvegarde."""
    print("[+] Génération de la paire de clés RSA-2048 (cela peut prendre ~30 secondes)...")
    n, e, d = generate_rsa_keypair(bits=2048)
    save_keys(n, e, d, pub_path=pub_path, priv_path=priv_path)
    print("[✓] Clés générées avec succès.")

# ─── POINT D'ENTRÉE CLI ──────────────────────────────────────────────────────

def _usage():
    print(__doc__)
    sys.exit(1)

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        _usage()

    cmd = args[0].lower()

    if cmd == "keygen":
        pub  = args[1] if len(args) > 1 else "public.key"
        priv = args[2] if len(args) > 2 else "private.key"
        keygen(pub, priv)

    elif cmd == "encrypt":
        if len(args) < 2:
            print("Usage: vault.py encrypt <fichier> [--pub public.key]")
            sys.exit(1)
        inp = args[1]
        out = inp + ".vault"
        pub = "public.key"
        if "--pub" in args:
            pub = args[args.index("--pub") + 1]
        encrypt_file(inp, out, pub_key_path=pub)

    elif cmd == "decrypt":
        if len(args) < 2:
            print("Usage: vault.py decrypt <fichier.vault> [--priv private.key]")
            sys.exit(1)
        inp  = args[1]
        base = inp.removesuffix(".vault")
        out  = base + "_decrypted" + (("." + base.split(".")[-1]) if "." in base else "")
        priv = "private.key"
        if "--priv" in args:
            priv = args[args.index("--priv") + 1]
        try:
            decrypt_file(inp, out, priv_key_path=priv)
        except ValueError as ve:
            print(f"\n{ve}")
            sys.exit(2)

    else:
        print(f"Commande inconnue : {cmd}")
        _usage()
