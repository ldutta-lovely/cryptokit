"""Generate example CTF challenges across each cryptography category."""

import base64
import hashlib
import json
import os
from pathlib import Path
import zlib
from Crypto.Util.number import getPrime

from cryptokit.classical import CaesarAttack, VigenereAttack
from cryptokit.utils import bytes_to_long, modinv, xor_repeating

CHALLENGES_DIR = Path("E:/cryptokit/examples/challenges")
CHALLENGES_DIR.mkdir(parents=True, exist_ok=True)


def generate_all():
    print("Generating challenge samples...")

    # 1. Encoding layers
    flag1 = b"flag{encoding_onion_peeled_cleanly}"
    enc1 = zlib.compress(flag1)
    enc2 = enc1.hex().encode("utf-8")
    enc3 = base64.b64encode(enc2)
    (CHALLENGES_DIR / "01_encoding_onion.txt").write_bytes(enc3)

    # 2. Caesar shift
    flag2 = "flag{caesar_cipher_shift_17_discovered}"
    caesar = CaesarAttack()
    ct2 = caesar.decrypt(flag2, -17)
    (CHALLENGES_DIR / "02_caesar.txt").write_text(ct2, encoding="utf-8")

    # 3. Vigenere
    flag3 = "The secret operative confirmed the extraction point and transmitted the message: flag{vigenere_kasiski_and_ioc_solved}!"
    vig = VigenereAttack()
    key3 = "AGY"
    # Encrypt
    enc_chars = []
    ki = 0
    for c in flag3:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            shift = ord(key3[ki % len(key3)]) - ord('A')
            enc_chars.append(chr(((ord(c) - base + shift) % 26) + base))
            ki += 1
        else:
            enc_chars.append(c)
    ct3 = "".join(enc_chars)
    (CHALLENGES_DIR / "03_vigenere.txt").write_text(ct3, encoding="utf-8")

    # 4. Repeating XOR
    flag4 = (
        b"Modern cryptography relies on hard computational problems. "
        b"Here is your prize: flag{repeating_xor_hamming_frequency_broken}!"
    )
    ct4 = xor_repeating(flag4, b"CTF")
    (CHALLENGES_DIR / "04_repeating_xor.hex").write_text(ct4.hex(), encoding="utf-8")

    # 5. RSA Fermat close primes
    flag5 = b"flag{fermat_close_primes_factored}"
    m5 = bytes_to_long(flag5)
    p5 = getPrime(256)
    q5 = p5 + 24
    while True:
        from sympy import isprime
        if isprime(q5):
            break
        q5 += 2
    n5 = p5 * q5
    e5 = 65537
    c5 = pow(m5, e5, n5)
    (CHALLENGES_DIR / "05_rsa_fermat.txt").write_text(f"n = {n5}\ne = {e5}\nc = {c5}\n", encoding="utf-8")

    # 6. RSA Wiener small d
    flag6 = b"flag{wiener_small_d_fractions_attack}"
    m6 = bytes_to_long(flag6)
    while True:
        p6 = getPrime(256)
        q6 = getPrime(256)
        if p6 == q6:
            continue
        n6 = p6 * q6
        phi6 = (p6 - 1) * (q6 - 1)
        d6 = getPrime(55)
        try:
            e6 = modinv(d6, phi6)
            if e6 > 1:
                break
        except Exception:
            continue
    c6 = pow(m6, e6, n6)
    (CHALLENGES_DIR / "06_rsa_wiener.txt").write_text(f"n = {n6}\ne = {e6}\nc = {c6}\n", encoding="utf-8")

    # 7. RSA Hastad Broadcast (e=3)
    flag7 = b"flag{hastad_crt_broadcast_3_keys}"
    m7 = bytes_to_long(flag7)
    e7 = 3
    moduli7 = []
    ciphertexts7 = []
    for _ in range(3):
        p7 = getPrime(256)
        q7 = getPrime(256)
        ni = p7 * q7
        moduli7.append(ni)
        ciphertexts7.append(pow(m7, e7, ni))
    hastad_data = {"e": e7, "moduli": moduli7, "ciphertexts": ciphertexts7}
    (CHALLENGES_DIR / "07_rsa_hastad.json").write_text(json.dumps(hastad_data, indent=2), encoding="utf-8")

    # 8. Hash Cracking with Rules
    # Password: "supersecret123"
    target_hash8 = hashlib.sha256(b"supersecret123").hexdigest()
    (CHALLENGES_DIR / "08_hash.txt").write_text(target_hash8 + "\n", encoding="utf-8")
    (CHALLENGES_DIR / "08_wordlist.txt").write_text("password\nadmin\nsupersecret\ndragon\n", encoding="utf-8")

    print(f"Generated 8 challenge samples in {CHALLENGES_DIR}")


if __name__ == "__main__":
    generate_all()
