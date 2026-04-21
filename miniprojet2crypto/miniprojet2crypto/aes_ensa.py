"""
aes_ensa.py — Variante AES-128 personnalisée (AES-ENSA)
========================================================
S-Box basée sur f(x) = (a*x + b) mod 256
où a et b sont dérivés des 2 premiers chiffres du matricule étudiant.

IMPORTANT : changer MATRICULE_A et MATRICULE_B selon votre matricule.
Exemple matricule "2301234" → a=2, b=3
"""

# ─── PARAMÈTRES PERSONNALISÉS ──────────────────────────────────────────────────
# Remplacez ces valeurs par les 2 premiers chiffres de VOTRE matricule
MATRICULE_A = 2   # premier chiffre  (doit être impair pour que la fonction soit bijective)
MATRICULE_B = 3   # deuxième chiffre

# ─── GÉNÉRATION DE LA S-BOX AFFINE ────────────────────────────────────────────

def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def generate_sbox(a: int, b: int) -> list[int]:
    """
    Génère une S-Box 256 entrées via f(x) = (a*x + b) mod 256.
    Pour que la S-Box soit une permutation, gcd(a, 256) doit être 1
    (i.e. a doit être impair).
    Si a est pair, on le force à a+1 pour garantir la bijectivité.
    """
    if _gcd(a, 256) != 1:
        a = a + 1 if (a + 1) % 2 != 0 else a + 2
        # s'assurer qu'il est impair
        if a % 2 == 0:
            a += 1
    sbox = [(a * x + b) % 256 for x in range(256)]
    return sbox

def generate_inv_sbox(sbox: list[int]) -> list[int]:
    """Inverse de la S-Box (pour le déchiffrement)."""
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

# S-Box et son inverse générées une seule fois
SBOX = generate_sbox(MATRICULE_A, MATRICULE_B)
INV_SBOX = generate_inv_sbox(SBOX)

# ─── TABLES GF(2^8) pour MixColumns ──────────────────────────────────────────

def _xtime(a: int) -> int:
    """Multiplication par 2 dans GF(2^8) avec polynôme réducteur 0x1B."""
    if a & 0x80:
        return ((a << 1) ^ 0x1B) & 0xFF
    return (a << 1) & 0xFF

def _gmul(a: int, b: int) -> int:
    """Multiplication de a et b dans GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

# ─── OPÉRATIONS AES DE BASE ───────────────────────────────────────────────────

def sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """Applique la S-Box personnalisée à chaque octet de la matrice d'état."""
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def shift_rows(state: list[list[int]]) -> list[list[int]]:
    """
    Décalage cyclique à gauche de la ligne i de i positions.
    Ligne 0 : pas de décalage
    Ligne 1 : 1 décalage
    Ligne 2 : 2 décalages
    Ligne 3 : 3 décalages
    """
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]

def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    """Décalage cyclique à droite."""
    return [
        state[0],
        state[1][-1:] + state[1][:-1],
        state[2][-2:] + state[2][:-2],
        state[3][-3:] + state[3][:-3],
    ]

def mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    MixColumns AES standard : multiplication par la matrice MDS dans GF(2^8).
    Matrice :
    [2 3 1 1]
    [1 2 3 1]
    [1 1 2 3]
    [3 1 1 2]
    """
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = _gmul(2, col[0]) ^ _gmul(3, col[1]) ^ col[2] ^ col[3]
        new_state[1][c] = col[0] ^ _gmul(2, col[1]) ^ _gmul(3, col[2]) ^ col[3]
        new_state[2][c] = col[0] ^ col[1] ^ _gmul(2, col[2]) ^ _gmul(3, col[3])
        new_state[3][c] = _gmul(3, col[0]) ^ col[1] ^ col[2] ^ _gmul(2, col[3])
    return new_state

def inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    InvMixColumns : matrice inverse dans GF(2^8).
    [14 11 13  9]
    [ 9 14 11 13]
    [13  9 14 11]
    [11 13  9 14]
    """
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = _gmul(14,col[0])^_gmul(11,col[1])^_gmul(13,col[2])^_gmul( 9,col[3])
        new_state[1][c] = _gmul( 9,col[0])^_gmul(14,col[1])^_gmul(11,col[2])^_gmul(13,col[3])
        new_state[2][c] = _gmul(13,col[0])^_gmul( 9,col[1])^_gmul(14,col[2])^_gmul(11,col[3])
        new_state[3][c] = _gmul(11,col[0])^_gmul(13,col[1])^_gmul( 9,col[2])^_gmul(14,col[3])
    return new_state

def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
    """XOR état avec la sous-clé du round."""
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]

# ─── KEY EXPANSION ────────────────────────────────────────────────────────────

# Constantes de round (Rcon) — standard AES
RCON = [
    [0x01,0x00,0x00,0x00], [0x02,0x00,0x00,0x00],
    [0x04,0x00,0x00,0x00], [0x08,0x00,0x00,0x00],
    [0x10,0x00,0x00,0x00], [0x20,0x00,0x00,0x00],
    [0x40,0x00,0x00,0x00], [0x80,0x00,0x00,0x00],
    [0x1B,0x00,0x00,0x00], [0x36,0x00,0x00,0x00],
]

def _sub_word(word: list[int]) -> list[int]:
    """Applique la S-Box ENSA à chaque octet d'un mot de 4 octets."""
    return [SBOX[b] for b in word]

def _rot_word(word: list[int]) -> list[int]:
    """Rotation cyclique gauche d'un mot."""
    return word[1:] + word[:1]

def key_expansion(key: bytes) -> list[list[list[int]]]:
    """
    Expansion de clé AES-128 → 11 sous-clés (matrices 4×4).
    Utilise la S-Box ENSA dans SubWord.
    """
    assert len(key) == 16, "La clé doit faire 128 bits (16 octets)"
    # W : 44 mots de 4 octets
    W = []
    for i in range(4):
        W.append(list(key[4*i : 4*i+4]))

    for i in range(4, 44):
        temp = W[i-1][:]
        if i % 4 == 0:
            temp = [a ^ b for a, b in zip(_sub_word(_rot_word(temp)), RCON[i//4 - 1])]
        else:
            pass  # AES-128 : pas de SubWord pour i non multiple de 4
        W.append([a ^ b for a, b in zip(W[i-4], temp)])

    # Transformer en 11 matrices 4×4 (colonne-major comme AES)
    round_keys = []
    for rnd in range(11):
        matrix = [[0]*4 for _ in range(4)]
        for c in range(4):
            for r in range(4):
                matrix[r][c] = W[rnd*4 + c][r]
        round_keys.append(matrix)
    return round_keys

# ─── CHIFFREMENT / DÉCHIFFREMENT D'UN BLOC ───────────────────────────────────

def _bytes_to_state(block: bytes) -> list[list[int]]:
    """Convertit 16 octets en matrice d'état 4×4 (colonne-major)."""
    state = [[0]*4 for _ in range(4)]
    for i, b in enumerate(block):
        state[i % 4][i // 4] = b
    return state

def _state_to_bytes(state: list[list[int]]) -> bytes:
    """Convertit matrice d'état 4×4 en 16 octets."""
    out = []
    for c in range(4):
        for r in range(4):
            out.append(state[r][c])
    return bytes(out)

def print_state(state: list[list[int]], label: str = ""):
    """Affiche la matrice d'état (utile pour débogage)."""
    if label:
        print(f"  [{label}]")
    for row in state:
        print("   " + " ".join(f"{b:02X}" for b in row))

def encrypt_block(block: bytes, round_keys: list, verbose: bool = False, round_print: set = None) -> bytes:
    """
    Chiffre un bloc de 16 octets avec AES-ENSA.
    Si verbose=True et round_print contient des numéros de rounds, affiche l'état.
    """
    if round_print is None:
        round_print = set()
    state = _bytes_to_state(block)

    # Round initial
    state = add_round_key(state, round_keys[0])

    for rnd in range(1, 11):
        state = sub_bytes(state)
        if verbose and rnd in round_print:
            print_state(state, f"Round {rnd} — après SubBytes")
        state = shift_rows(state)
        if verbose and rnd in round_print:
            print_state(state, f"Round {rnd} — après ShiftRows")
        if rnd < 10:
            state = mix_columns(state)
            if verbose and rnd in round_print:
                print_state(state, f"Round {rnd} — après MixColumns")
        state = add_round_key(state, round_keys[rnd])
        if verbose and rnd in round_print:
            print_state(state, f"Round {rnd} — après AddRoundKey (état final du round)")

    return _state_to_bytes(state)

def decrypt_block(block: bytes, round_keys: list) -> bytes:
    """Déchiffre un bloc de 16 octets avec AES-ENSA (inverse)."""
    state = _bytes_to_state(block)
    state = add_round_key(state, round_keys[10])

    for rnd in range(9, -1, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        if rnd > 0:
            state = inv_mix_columns(state)

    return _state_to_bytes(state)

# ─── MODE CBC ────────────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """Supprime le PKCS#7 padding."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding PKCS#7 invalide")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 corrompu")
    return data[:-pad_len]

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Chiffrement AES-ENSA en mode CBC."""
    rk = key_expansion(key)
    padded = pkcs7_pad(plaintext)
    ciphertext = b""
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc = encrypt_block(block, rk)
        ciphertext += enc
        prev = enc
    return ciphertext

def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Déchiffrement AES-ENSA en mode CBC."""
    rk = key_expansion(key)
    plaintext = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = decrypt_block(block, rk)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext += plain_block
        prev = block
    return pkcs7_unpad(plaintext)
