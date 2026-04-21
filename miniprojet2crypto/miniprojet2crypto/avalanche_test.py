"""
avalanche_test.py — Test d'Effet d'Avalanche AES-ENSA
=====================================================
Prouve qu'en changeant 1 seul bit de la clé AES,
plus de 50% des octets du fichier chiffré changent.
"""

import secrets
import os
from aes_ensa import cbc_encrypt, MATRICULE_A, MATRICULE_B

def flip_bit(data: bytes, bit_position: int) -> bytes:
    """Inverse un bit à la position donnée dans data."""
    ba = bytearray(data)
    byte_idx = bit_position // 8
    bit_idx  = bit_position % 8
    ba[byte_idx] ^= (1 << bit_idx)
    return bytes(ba)

def hamming_distance_bytes(b1: bytes, b2: bytes) -> int:
    """Nombre de bits différents entre deux chaînes d'octets."""
    assert len(b1) == len(b2)
    total = 0
    for x, y in zip(b1, b2):
        diff = x ^ y
        total += bin(diff).count('1')
    return total

def bytes_changed(b1: bytes, b2: bytes) -> int:
    """Nombre d'octets différents entre deux chaînes."""
    return sum(1 for x, y in zip(b1, b2) if x != y)

def run_avalanche_test():
    print("=" * 60)
    print("  TEST D'EFFET D'AVALANCHE — AES-ENSA")
    print("=" * 60)
    print(f"  Paramètres matricule : a={MATRICULE_A}, b={MATRICULE_B}")
    print()

    # Données de test
    plaintext = b"VaultGCSE2 Avalanche Test - Message fixe pour le test de diffusion des changements de cle AES."
    plaintext = plaintext + b'\x00' * (16 - len(plaintext) % 16)  # align bloc
    iv = secrets.token_bytes(16)

    print(f"  Taille du message  : {len(plaintext)} octets")
    print(f"  IV (hex)           : {iv.hex()}")
    print()

    results = []

    for bit_pos in range(128):  # tester chaque bit de la clé sur quelques exemples
        key_orig = secrets.token_bytes(16)
        key_flip = flip_bit(key_orig, bit_pos)

        ct_orig = cbc_encrypt(plaintext, key_orig, iv)
        ct_flip = cbc_encrypt(plaintext, key_flip, iv)

        changed_bytes = bytes_changed(ct_orig, ct_flip)
        changed_bits  = hamming_distance_bytes(ct_orig, ct_flip)
        pct_bytes = 100 * changed_bytes / len(ct_orig)
        pct_bits  = 100 * changed_bits  / (len(ct_orig) * 8)

        results.append((bit_pos, pct_bytes, pct_bits))

    # Résumé
    avg_bytes = sum(r[1] for r in results) / len(results)
    avg_bits  = sum(r[2] for r in results) / len(results)
    min_bytes = min(r[1] for r in results)
    max_bytes = max(r[1] for r in results)

    print(f"  Résultats sur {len(results)} tests (1 flip de bit par bit de clé) :")
    print(f"  {'─'*50}")
    print(f"  % octets modifiés  : moyenne={avg_bytes:.1f}%  min={min_bytes:.1f}%  max={max_bytes:.1f}%")
    print(f"  % bits modifiés    : moyenne={avg_bits:.1f}%")
    print()

    if avg_bytes >= 50:
        print(f"  [✓] Effet d'avalanche CONFIRMÉ : {avg_bytes:.1f}% des octets changent en moyenne")
        print(f"      (seuil requis : > 50%)")
    else:
        print(f"  [✗] Effet d'avalanche INSUFFISANT : seulement {avg_bytes:.1f}%")

    # Affichage détaillé de quelques cas représentatifs
    print()
    print(f"  {'─'*50}")
    print(f"  Détail — 10 premiers bits testés :")
    print(f"  {'Bit':>5} | {'Octets modifiés':>15} | {'Bits modifiés':>13}")
    print(f"  {'─'*40}")
    for bit_pos, pct_bytes, pct_bits in results[:10]:
        print(f"  {bit_pos:>5} | {pct_bytes:>13.1f}% | {pct_bits:>11.1f}%")

    print()
    print("  [Note] L'effet d'avalanche dans AES standard est ~50% même avec")
    print("  la S-Box affine, car MixColumns + ShiftRows assurent la diffusion.")
    print("  La faiblesse de la S-Box affine est la linéarité, pas la diffusion.")
    print()

    # Enregistrer dans un fichier rapport
    with open("avalanche_results.txt", "w") as f:
        f.write("TEST D'EFFET D'AVALANCHE — AES-ENSA\n")
        f.write(f"Paramètres : a={MATRICULE_A}, b={MATRICULE_B}\n\n")
        f.write(f"Moyenne octets modifiés : {avg_bytes:.2f}%\n")
        f.write(f"Moyenne bits modifiés   : {avg_bits:.2f}%\n\n")
        f.write(f"{'Bit':>5} | {'% octets':>10} | {'% bits':>8}\n")
        for bit_pos, pb, pbt in results:
            f.write(f"{bit_pos:>5} | {pb:>9.2f}% | {pbt:>7.2f}%\n")
    print("  [✓] Résultats sauvegardés dans avalanche_results.txt")

if __name__ == "__main__":
    run_avalanche_test()
