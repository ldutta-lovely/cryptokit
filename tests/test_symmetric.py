"""Tests for symmetric cryptography utilities and attacks."""

import hashlib
import os
from Crypto.Cipher import AES
import pytest

from cryptokit.symmetric import (
    pkcs7_pad,
    pkcs7_unpad,
    is_pkcs7_padded,
    detect_ecb,
    ecb_byte_at_a_time,
    cbc_bit_flip,
    cbc_padding_oracle_decrypt,
    aes_brute_force,
)


def test_pkcs7_padding():
    data = b"YELLOW SUBMARINE"
    padded = pkcs7_pad(data, 20)
    assert len(padded) == 20
    assert padded == data + b"\x04\x04\x04\x04"
    assert is_pkcs7_padded(padded, 20)
    assert pkcs7_unpad(padded, 20) == data

    # Complete block adds full padding block
    block16 = pkcs7_pad(b"A" * 16, 16)
    assert len(block16) == 32
    assert block16.endswith(b"\x10" * 16)

    # Invalid padding check
    with pytest.raises(ValueError):
        pkcs7_unpad(b"YELLOW SUBMARINE\x05\x05\x05\x05", 20)


def test_detect_ecb():
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)

    # Repeating plaintext: "A" * 64 produces 4 identical 16-byte blocks
    pt = b"A" * 64
    ct = cipher.encrypt(pt)

    res = detect_ecb(ct)
    assert res["is_ecb"] is True
    assert res["duplicate_blocks"] == 3
    assert res["confidence"] > 0.5


def test_ecb_byte_at_a_time():
    secret_key = os.urandom(16)
    secret_flag = b"flag{ecb_byte_by_byte_suffix}"

    def mock_oracle(prefix: bytes) -> bytes:
        cipher = AES.new(secret_key, AES.MODE_ECB)
        data = pkcs7_pad(prefix + secret_flag)
        return cipher.encrypt(data)

    recovered = ecb_byte_at_a_time(mock_oracle, block_size=16, max_length=64)
    assert secret_flag in recovered


def test_cbc_bit_flip():
    key = os.urandom(16)
    iv = os.urandom(16)

    # Ciphertext structure:
    # Block 0: IV
    # Block 1: "comment1=cooking"
    # Block 2: "%20movie;user_id"
    # Block 3: "=123;role=user;a"
    orig_text = b"comment1=cooking%20movie;user_id=123;role=user;a"
    padded = pkcs7_pad(orig_text, 16)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = iv + cipher.encrypt(padded)

    # We want to flip "role=user" to "role=admin"
    # Locate where "role=user" appears in orig_text
    target_pos = orig_text.find(b"role=user") + 16  # +16 because IV is prepended
    orig_substr = b"role=user"
    des_substr = b"role=admi"

    flipped_ct = cbc_bit_flip(ct, orig_substr, des_substr, offset=target_pos, block_size=16)

    # Decrypt modified ciphertext
    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv=flipped_ct[:16])
    decrypted = decrypt_cipher.decrypt(flipped_ct[16:])
    assert b"role=admi" in decrypted


def test_cbc_padding_oracle():
    key = os.urandom(16)
    iv = os.urandom(16)
    secret_flag = b"flag{padding_oracle_block_by_block}"
    padded = pkcs7_pad(secret_flag, 16)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = iv + cipher.encrypt(padded)

    def mock_padding_oracle(test_ct: bytes) -> bool:
        if len(test_ct) < 32 or len(test_ct) % 16 != 0:
            return False
        test_iv = test_ct[:16]
        test_body = test_ct[16:]
        c = AES.new(key, AES.MODE_CBC, iv=test_iv)
        pt = c.decrypt(test_body)
        return is_pkcs7_padded(pt, 16)

    recovered = cbc_padding_oracle_decrypt(ciphertext, mock_padding_oracle, block_size=16)
    assert secret_flag in recovered


def test_aes_brute_force():
    key = hashlib.md5(b"password123").digest()
    flag = b"flag{aes_dictionary_attack_success}"
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pkcs7_pad(flag))

    wordlist = ["admin", "secret", "password123", "dragon", "123456"]
    candidates = aes_brute_force(ct, wordlist, mode="ECB", top=3)

    assert len(candidates) > 0
    assert candidates[0].plaintext == flag
    assert candidates[0].params["password"] == "password123"
