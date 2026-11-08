"""Tests for cryptokit.classical cipher attacks."""

import string
from cryptokit.classical import (
    CaesarAttack,
    AtbashAttack,
    AffineAttack,
    RailFenceAttack,
    ScytaleAttack,
    ColumnarTranspositionAttack,
    VigenereAttack,
    MonoalphabeticSubstitutionAttack,
    BeaufortAttack,
    AutokeyAttack,
)


def test_caesar():
    text = "flag{caesar_cipher_is_broken_instantly}"
    # Shift by 13 (ROT13)
    attack = CaesarAttack()
    shifted = attack.decrypt(text, -13)  # Encrypt with shift 13

    candidates = attack.run(shifted)
    assert len(candidates) > 0
    assert candidates[0].plaintext.decode() == text
    assert candidates[0].params["shift"] == 13


def test_atbash():
    text = "flag{atbash_alphabet_inversion}"
    attack = AtbashAttack()
    enc = attack.decrypt(text)
    res = attack.run(enc)
    assert res[0].plaintext.decode() == text


def test_affine():
    text = "flag{affine_ciphers_are_solved_easily}"
    attack = AffineAttack()
    # Encrypt: C = (a * P + b) % 26
    # Decrypt method in attack does: P = a_inv * (C - b) % 26
    # To encrypt with a=5, b=8:
    a, b = 5, 8
    enc_chars = []
    for c in text:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            enc_chars.append(chr(((a * (ord(c) - base) + b) % 26) + base))
        else:
            enc_chars.append(c)
    ct = "".join(enc_chars)

    candidates = attack.run(ct, top=3)
    assert candidates[0].plaintext.decode() == text
    assert candidates[0].params["a"] == 5
    assert candidates[0].params["b"] == 8


def test_rail_fence():
    text = "flag{rail_fence_zig_zag_recovery}"
    attack = RailFenceAttack()

    # Encrypt with 3 rails
    rails = 3
    pattern = []
    r, down = 0, True
    for _ in text:
        pattern.append(r)
        if r == 0:
            down = True
        elif r == rails - 1:
            down = False
        r += 1 if down else -1
    ct = "".join("".join(text[i] for i, rail_idx in enumerate(pattern) if rail_idx == r_i) for r_i in range(rails))

    candidates = attack.run(ct, top=5)
    match = [c for c in candidates if c.plaintext.decode() == text]
    assert len(match) > 0
    assert match[0].params["rails"] == 3


def test_scytale():
    text = "flag{scytale_rod_transposition_123}"
    attack = ScytaleAttack()
    # Encrypt diameter = 5
    diameter = 5
    rows = (len(text) + diameter - 1) // diameter
    cols = diameter
    matrix = [[" "] * cols for _ in range(rows)]
    for i, c in enumerate(text):
        matrix[i // cols][i % cols] = c
    ct = "".join("".join(matrix[r][c] for r in range(rows)) for c in range(cols))

    candidates = attack.run(ct)
    match = [c for c in candidates if c.plaintext.decode() == text]
    assert len(match) > 0


def test_columnar_transposition():
    text = "flag{columnar_permutations}"
    attack = ColumnarTranspositionAttack()
    perm = (1, 0, 2)
    enc = attack.encrypt(text, perm)
    candidates = attack.run(enc, max_key_len=3, top=5)
    found = any(c.plaintext.decode() == text for c in candidates)
    assert found


def test_vigenere():
    text = (
        "The quick brown fox jumps over the lazy dog and discovers the secret flag: "
        "flag{vigenere_frequency_analysis_succeeds}!"
    )
    attack = VigenereAttack()
    key = "CTF"
    # Encrypt
    enc_chars = []
    ki = 0
    for c in text:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            shift = ord(key[ki % len(key)].upper()) - ord('A')
            enc_chars.append(chr(((ord(c) - base + shift) % 26) + base))
            ki += 1
        else:
            enc_chars.append(c)
    ct = "".join(enc_chars)

    # Solve with crib
    candidates = attack.run(ct, crib="flag{")
    assert len(candidates) > 0
    found = any("flag{vigenere_frequency" in c.plaintext.decode() for c in candidates)
    assert found


def test_beaufort_and_autokey():
    text = "flag{beaufort_and_autokey_classical_ciphers}"
    b_attack = BeaufortAttack()
    b_key = "SECRET"
    # Beaufort is self-reciprocal if using same key
    ct_b = b_attack.decrypt(text, b_key)
    res_b = b_attack.run(ct_b, key=b_key)
    assert res_b[0].plaintext.decode() == text

    a_attack = AutokeyAttack()
    primer = "KITTEN"
    # Encrypt with autokey:
    stream = list(primer.upper())
    ki = 0
    enc_a = []
    for c in text:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            shift = ord(stream[ki]) - ord('A')
            enc_a.append(chr(((ord(c) - base + shift) % 26) + base))
            stream.append(c.upper())
            ki += 1
        else:
            enc_a.append(c)
    ct_a = "".join(enc_a)
    res_a = a_attack.run(ct_a, primer=primer)
    assert res_a[0].plaintext.decode() == text
