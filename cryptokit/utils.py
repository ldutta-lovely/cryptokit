"""Mathematical, bitwise, and formatting utilities for cryptokit."""

from __future__ import annotations

import math
import shutil
from typing import Generator, Sequence

# Check for gmpy2 acceleration
try:
    import gmpy2

    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False


def bytes_to_long(data: bytes) -> int:
    """Convert big-endian bytes to an integer."""
    return int.from_bytes(data, byteorder="big")


def long_to_bytes(val: int, blocksize: int = 0) -> bytes:
    """Convert an integer to big-endian bytes, optionally padded to blocksize bytes."""
    if val < 0:
        raise ValueError("Cannot convert negative integer to bytes")
    if val == 0:
        res = b"\x00"
    else:
        length = (val.bit_length() + 7) // 8
        res = val.to_bytes(length, byteorder="big")

    if blocksize > 0 and len(res) < blocksize:
        res = b"\x00" * (blocksize - len(res)) + res
    return res


def xgcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm.

    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    x1, y1 = 1, 0
    x2, y2 = 0, 1
    while b != 0:
        q = a // b
        a, b = b, a % b
        x1, x2 = x2, x1 - q * x2
        y1, y2 = y2, y1 - q * y2
    return a, x1, y1


def gcd(a: int, b: int) -> int:
    """Return greatest common divisor of a and b."""
    return math.gcd(a, b)


def modinv(a: int, m: int) -> int:
    """Compute modular inverse of a modulo m such that (a * inv) % m == 1.

    Raises ValueError if inverse does not exist.
    """
    if m <= 0:
        raise ValueError("Modulus must be positive")
    try:
        return pow(a, -1, m)
    except (ValueError, TypeError):
        g, x, _ = xgcd(a % m, m)
        if g != 1:
            raise ValueError(f"Modular inverse does not exist for {a} mod {m} (gcd={g})")
        return x % m


def crt(remainders: Sequence[int], moduli: Sequence[int]) -> int:
    """Chinese Remainder Theorem for pairwise coprime moduli.

    Finds x such that x = r_i (mod m_i) for all i.
    """
    if len(remainders) != len(moduli):
        raise ValueError("Remainders and moduli lists must have the same length")
    if not moduli:
        raise ValueError("Moduli list cannot be empty")

    prod = 1
    for m in moduli:
        prod *= m

    result = 0
    for r, m in zip(remainders, moduli):
        p = prod // m
        result += r * p * modinv(p, m)
    return result % prod


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Compute the integer k-th root of n: (floor(n**(1/k)), is_exact).

    Uses gmpy2.iroot if installed; otherwise falls back to exact integer binary search / Newton.
    """
    if n < 0:
        raise ValueError("Cannot compute root of negative integer")
    if k <= 0:
        raise ValueError("Root degree k must be positive")
    if n == 0:
        return 0, True
    if k == 1:
        return n, True

    if HAVE_GMPY2:
        root, is_exact = gmpy2.iroot(n, k)
        return int(root), bool(is_exact)

    # Pure-Python integer k-th root via binary search + Newton refinement
    # Initial estimate using bit lengths
    bits = (n.bit_length() + k - 1) // k
    low = 1 << (bits - 1)
    high = 1 << (bits + 1)

    while low <= high:
        mid = (low + high) // 2
        p = mid**k
        if p == n:
            return mid, True
        elif p < n:
            low = mid + 1
        else:
            high = mid - 1

    root = high
    return root, (root**k == n)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Bitwise XOR between two byte sequences up to the length of the shorter one."""
    return bytes(x ^ y for x, y in zip(a, b))


def xor_single(data: bytes, key: int) -> bytes:
    """XOR every byte in data with an integer key in range 0..255."""
    k = key & 0xFF
    return bytes(b ^ k for b in data)


def xor_repeating(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating byte sequence key."""
    if not key:
        return data
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def chunk_bytes(data: bytes, size: int) -> list[bytes]:
    """Split data into consecutive chunks of length `size`."""
    if size <= 0:
        raise ValueError("Chunk size must be positive")
    return [data[i : i + size] for i in range(0, len(data), size)]


def hexdump(data: bytes, length: int = 16) -> str:
    """Format bytes as canonical hexdump output."""
    lines: list[str] = []
    for i in range(0, len(data), length):
        chunk = data[i : i + length]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex representation to align ASCII view
        pad = "   " * (length - len(chunk))
        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_bytes}{pad}  |{ascii_repr}|")
    return "\n".join(lines)


def continued_fractions(numerator: int, denominator: int) -> Generator[int, None, None]:
    """Generate the continued fraction coefficients [a0, a1, a2, ...] of numerator/denominator."""
    a, b = numerator, denominator
    while b != 0:
        q = a // b
        yield q
        a, b = b, a - q * b


def convergents(numerator: int, denominator: int) -> Generator[tuple[int, int], None, None]:
    """Generate successive convergents (p_k, q_k) of numerator/denominator using continued fractions."""
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for q in continued_fractions(numerator, denominator):
        p = q * p1 + p0
        denom = q * q1 + q0
        yield p, denom
        p0, p1 = p1, p
        q0, q1 = q1, denom


def is_sagemath_available() -> bool:
    """Return True if SageMath is detected in the system PATH."""
    return shutil.which("sage") is not None
