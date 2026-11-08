"""Tests for cryptokit.utils."""

import pytest
from cryptokit.utils import (
    bytes_to_long,
    long_to_bytes,
    modinv,
    xgcd,
    gcd,
    crt,
    iroot,
    xor_bytes,
    xor_single,
    xor_repeating,
    chunk_bytes,
    hexdump,
    continued_fractions,
    convergents,
)


def test_bytes_long_roundtrip():
    data = b"Hello, CTF world!"
    val = bytes_to_long(data)
    recovered = long_to_bytes(val)
    assert recovered == data

    assert long_to_bytes(0) == b"\x00"
    assert bytes_to_long(b"\x00") == 0

    # Test padding
    padded = long_to_bytes(42, blocksize=8)
    assert len(padded) == 8
    assert padded == b"\x00" * 7 + b"*"


def test_xgcd_and_gcd():
    a, b = 240, 46
    g, x, y = xgcd(a, b)
    assert g == gcd(a, b)
    assert a * x + b * y == g


def test_modinv():
    a, m = 17, 3120
    inv = modinv(a, m)
    assert (a * inv) % m == 1

    with pytest.raises(ValueError):
        modinv(4, 8)  # gcd(4,8) = 4 != 1


def test_crt():
    # x = 2 (mod 3), x = 3 (mod 5), x = 2 (mod 7) => x = 23 (mod 105)
    r = [2, 3, 2]
    m = [3, 5, 7]
    sol = crt(r, m)
    assert sol == 23
    for rem, mod in zip(r, m):
        assert sol % mod == rem


def test_iroot():
    # Exact roots
    root, is_exact = iroot(1000000, 3)
    assert is_exact is True
    assert root == 100

    root, is_exact = iroot(2**128, 4)
    assert is_exact is True
    assert root == 2**32

    # Inexact roots
    root, is_exact = iroot(26, 2)
    assert is_exact is False
    assert root == 5

    root, is_exact = iroot(0, 3)
    assert is_exact is True
    assert root == 0


def test_xor_helpers():
    a = b"AAAA"
    b = b"BBBB"
    assert xor_bytes(a, b) == bytes([ord("A") ^ ord("B")] * 4)

    msg = b"SecretMessage"
    k = 0x42
    enc = xor_single(msg, k)
    assert xor_single(enc, k) == msg

    rep_key = b"KEY"
    rep_enc = xor_repeating(msg, rep_key)
    assert xor_repeating(rep_enc, rep_key) == msg


def test_chunking_and_hexdump():
    data = b"0123456789abcdefghij"
    chunks = chunk_bytes(data, 5)
    assert len(chunks) == 4
    assert chunks[0] == b"01234"
    assert chunks[-1] == b"fghij"

    hd = hexdump(b"test1234")
    assert "74 65 73 74 31 32 33 34" in hd
    assert "|test1234|" in hd


def test_continued_fractions_and_convergents():
    # 355 / 113 is approximation of pi
    cf = list(continued_fractions(355, 113))
    assert cf == [3, 7, 16]

    convs = list(convergents(355, 113))
    # Last convergent must equal 355, 113
    assert convs[-1] == (355, 113)
