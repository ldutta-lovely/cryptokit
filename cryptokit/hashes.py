"""Hash utilities: identification, dictionary cracking with rules, and hash length extension for MD5, SHA-1, and SHA-256."""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Callable, Sequence


# --- Hash Type Identification ---

def identify_hash(hash_str: str) -> list[str]:
    """Identify possible hash algorithms from hash string length and structure."""
    h = hash_str.strip()
    results: list[str] = []

    # Password hash format checks
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return ["bcrypt"]
    if h.startswith("$6$"):
        return ["sha512crypt"]
    if h.startswith("$5$"):
        return ["sha256crypt"]
    if h.startswith("$1$"):
        return ["md5crypt"]
    if h.startswith(("$argon2id$", "$argon2i$")):
        return ["argon2"]

    # Hex checks
    is_hex = all(c in "0123456789abcdefABCDEF" for c in h)
    length = len(h)

    if is_hex:
        if length == 32:
            results.extend(["MD5", "NTLM", "MD4"])
        elif length == 40:
            results.extend(["SHA-1", "RIPEMD-160"])
        elif length == 56:
            results.extend(["SHA-224", "SHA3-224"])
        elif length == 64:
            results.extend(["SHA-256", "SHA3-256", "BLAKE2s"])
        elif length == 96:
            results.extend(["SHA-384", "SHA3-384"])
        elif length == 128:
            results.extend(["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"])

    return results if results else ["Unknown"]


# --- Dictionary Cracker with Simple Rules ---

def apply_rules(word: str) -> list[str]:
    """Generate rule-based mutations for a candidate word."""
    candidates = [word]

    # Casing
    candidates.append(word.lower())
    candidates.append(word.upper())
    candidates.append(word.capitalize())

    # Common leetspeak substitutions
    # 1. Vowels only (very common in passwords, e.g. "s3cr3t")
    vowel_map = {"a": "4", "e": "3", "i": "1", "o": "0"}
    vowel_word = "".join(vowel_map.get(c.lower(), c) for c in word)
    if vowel_word != word:
        candidates.append(vowel_word)

    # 2. Full leetspeak (including s->5, t->7)
    leet_map = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
    leet_word = "".join(leet_map.get(c.lower(), c) for c in word)
    if leet_word != word and leet_word != vowel_word:
        candidates.append(leet_word)

    # Common suffixes
    for suffix in ("1", "123", "!", "?", "2024", "2025", "2026"):
        candidates.append(word + suffix)

    # Deduplicate while preserving order
    seen = set()
    unique_candidates = []
    for cand in candidates:
        if cand not in seen:
            seen.add(cand)
            unique_candidates.append(cand)
    return unique_candidates


def hash_func_by_name(algo: str) -> Callable[[bytes], str]:
    """Return hashing function producing hex digest for specified algorithm name."""
    algo_lower = algo.lower()
    if algo_lower in ("md5",):
        return lambda b: hashlib.md5(b).hexdigest()
    if algo_lower in ("sha1", "sha-1"):
        return lambda b: hashlib.sha1(b).hexdigest()
    if algo_lower in ("sha256", "sha-256"):
        return lambda b: hashlib.sha256(b).hexdigest()
    if algo_lower in ("sha512", "sha-512"):
        return lambda b: hashlib.sha512(b).hexdigest()
    if algo_lower in ("ntlm",):
        # NTLM is MD4 of UTF-16LE encoded password
        return lambda b: hashlib.new("md4", b.decode("utf-8", errors="replace").encode("utf-16le")).hexdigest()
    return lambda b: hashlib.new(algo_lower, b).hexdigest()


def crack_hash(
    target_hash: str,
    wordlist: Sequence[str],
    algorithm: str | None = None,
    use_rules: bool = True,
) -> tuple[str, str] | None:
    """Dictionary crack a target hash with optional transformation rules."""
    target_clean = target_hash.strip().lower()

    # If algorithm not specified, deduce from length
    if algorithm is None:
        possible = identify_hash(target_clean)
        if not possible or possible == ["Unknown"]:
            return None
        algos_to_try = possible
    else:
        algos_to_try = [algorithm]

    for algo in algos_to_try:
        try:
            h_fn = hash_func_by_name(algo)
        except Exception:
            continue

        for base_word in wordlist:
            variants = apply_rules(base_word) if use_rules else [base_word]
            for variant in variants:
                if h_fn(variant.encode("utf-8")) == target_clean:
                    return variant, algo

    return None


# --- Merkle-Damgard Hash Length Extension Attacks (MD5, SHA-1, SHA-256) ---

def md_padding(total_byte_length: int, endian: str = "little") -> bytes:
    """Generate Merkle-Damgard padding (0x80, zero bytes, 64-bit length)."""
    pad_len = (55 - (total_byte_length % 64)) % 64
    padding = b"\x80" + (b"\x00" * pad_len)
    bit_len = total_byte_length * 8
    if endian == "little":
        padding += struct.pack("<Q", bit_len)
    else:
        padding += struct.pack(">Q", bit_len)
    return padding


# MD5 Helpers
def _md5_compress(state: list[int], block: bytes) -> list[int]:
    """Single-block MD5 compression step on 64-byte block."""
    import math

    a, b, c, d = state
    X = list(struct.unpack("<16I", block))

    def left_rot(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    T = [int(4294967296 * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]

    # Round 1
    s1 = [7, 12, 17, 22] * 4
    for i in range(16):
        f = (b & c) | (~b & d)
        g = i
        to_rot = (a + f + T[i] + X[g]) & 0xFFFFFFFF
        a, d, c, b = d, c, b, (b + left_rot(to_rot, s1[i])) & 0xFFFFFFFF

    # Round 2
    s2 = [5, 9, 14, 20] * 4
    for i in range(16, 32):
        f = (d & b) | (~d & c)
        g = (5 * i + 1) % 16
        to_rot = (a + f + T[i] + X[g]) & 0xFFFFFFFF
        a, d, c, b = d, c, b, (b + left_rot(to_rot, s2[i - 16])) & 0xFFFFFFFF

    # Round 3
    s3 = [4, 11, 16, 23] * 4
    for i in range(32, 48):
        f = b ^ c ^ d
        g = (3 * i + 5) % 16
        to_rot = (a + f + T[i] + X[g]) & 0xFFFFFFFF
        a, d, c, b = d, c, b, (b + left_rot(to_rot, s3[i - 32])) & 0xFFFFFFFF

    # Round 4
    s4 = [6, 10, 15, 21] * 4
    for i in range(48, 64):
        f = c ^ (b | ~d)
        g = (7 * i) % 16
        to_rot = (a + f + T[i] + X[g]) & 0xFFFFFFFF
        a, d, c, b = d, c, b, (b + left_rot(to_rot, s4[i - 48])) & 0xFFFFFFFF

    return [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
    ]


# SHA-1 Helpers
def _sha1_compress(state: list[int], block: bytes) -> list[int]:
    """Single-block SHA-1 compression step on 64-byte block."""
    h0, h1, h2, h3, h4 = state
    w = list(struct.unpack(">16I", block)) + [0] * 64

    def left_rot(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    for i in range(16, 80):
        w[i] = left_rot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(80):
        if 0 <= i <= 19:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = (left_rot(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = left_rot(b, 30)
        b = a
        a = temp

    return [
        (h0 + a) & 0xFFFFFFFF,
        (h1 + b) & 0xFFFFFFFF,
        (h2 + c) & 0xFFFFFFFF,
        (h3 + d) & 0xFFFFFFFF,
        (h4 + e) & 0xFFFFFFFF,
    ]


# SHA-256 Helpers
def _sha256_compress(state: list[int], block: bytes) -> list[int]:
    """Single-block SHA-256 compression step on 64-byte block."""
    K = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ]

    def ror(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    return [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
        (state[5] + f) & 0xFFFFFFFF,
        (state[6] + g) & 0xFFFFFFFF,
        (state[7] + h) & 0xFFFFFFFF,
    ]


def hash_length_extension(
    algo: str,
    original_hash: str,
    original_message: bytes,
    key_length: int,
    append_data: bytes,
) -> tuple[bytes, str]:
    """Execute hash length extension attack for MD5, SHA-1, or SHA-256.

    Returns (forged_payload, forged_hash_hex).
    The forged payload is: original_message + glue_padding + append_data.
    """
    algo_lower = algo.lower()
    total_orig_len = key_length + len(original_message)
    endian = "little" if algo_lower == "md5" else "big"
    glue_pad = md_padding(total_orig_len, endian=endian)

    # Reconstruct state from original hash
    raw_hash = bytes.fromhex(original_hash.strip())

    if algo_lower == "md5":
        state = list(struct.unpack("<4I", raw_hash))
        compress_fn = _md5_compress
        unpack_fmt = "<4I"
    elif algo_lower in ("sha1", "sha-1"):
        state = list(struct.unpack(">5I", raw_hash))
        compress_fn = _sha1_compress
        unpack_fmt = ">5I"
    elif algo_lower in ("sha256", "sha-256"):
        state = list(struct.unpack(">8I", raw_hash))
        compress_fn = _sha256_compress
        unpack_fmt = ">8I"
    else:
        raise ValueError(f"Unsupported length extension algorithm: {algo}")

    # Now pad the appended data with the new total length
    new_total_len = total_orig_len + len(glue_pad) + len(append_data)
    appended_stream = append_data + md_padding(new_total_len, endian=endian)

    # Process appended stream in 64-byte chunks
    for i in range(0, len(appended_stream), 64):
        block = appended_stream[i : i + 64]
        state = compress_fn(state, block)

    forged_hash = struct.pack(unpack_fmt, *state).hex()
    forged_payload = original_message + glue_pad + append_data
    return forged_payload, forged_hash
