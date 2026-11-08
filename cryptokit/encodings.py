"""Multi-codec detection, decoding, and recursive peeling engine."""

from __future__ import annotations

import bz2
import codecs
import gzip
import html
import re
import urllib.parse
import zlib
from typing import Callable, Sequence

from cryptokit.base import Candidate
from cryptokit.scoring import rank, score

# Base58 Bitcoin alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}

# Morse code dictionary
MORSE_CODE_DICT = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    "0": "-----", "{": "-.--.", "}": "-.--.-", "_": "..--.-", "?": "..--..",
    "/": "-..-.", "-": "-....-", ".": ".-.-.-", ",": "--..--",
}
REV_MORSE = {v: k for k, v in MORSE_CODE_DICT.items()}

# Bacon cipher dictionaries (24-letter classical and 26-letter unique)
BACON_26 = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
    "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
    "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
    "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y",
    "BBAAB": "Z",
}


def decode_base58(s: str) -> bytes:
    """Decode a Base58 string into bytes."""
    s = s.strip()
    if not s or not all(c in B58_MAP for c in s):
        raise ValueError("Invalid Base58 characters")
    num = 0
    for char in s:
        num = num * 58 + B58_MAP[char]

    # Convert to bytes
    res = []
    while num > 0:
        res.append(num & 0xFF)
        num >>= 8
    res = bytes(reversed(res))

    # Add leading zero bytes for leading '1's
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return (b"\x00" * pad) + res


def decode_morse(s: str) -> bytes:
    """Decode Morse code string with space or slash separation."""
    s = s.strip()
    # Normalize separators
    words = re.split(r"\s*/\s*|\s{2,}", s)
    decoded_words = []
    for word in words:
        letters = word.strip().split()
        if not letters or not all(l in REV_MORSE for l in letters):
            raise ValueError("Invalid Morse tokens")
        decoded_words.append("".join(REV_MORSE[l] for l in letters))
    if not decoded_words:
        raise ValueError("Empty Morse")
    return " ".join(decoded_words).encode("utf-8")


def decode_rot47(s: str) -> bytes:
    """Decode ROT47 string."""
    res = []
    for c in s:
        code = ord(c)
        if 33 <= code <= 126:
            res.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            res.append(c)
    return "".join(res).encode("utf-8")


def decode_bacon(s: str) -> bytes:
    """Decode Bacon cipher with A/B, 0/1, or case distinction."""
    # Strip spaces
    clean = re.sub(r"\s+", "", s)
    if len(clean) < 5:
        raise ValueError("Too short for Bacon")

    # If binary 0/1
    if set(clean).issubset({"0", "1"}):
        clean = clean.replace("0", "A").replace("1", "B")
    elif set(clean.upper()).issubset({"A", "B"}):
        clean = clean.upper()
    else:
        # Check case-based steganography if letters only
        letters = [c for c in clean if c.isalpha()]
        if len(letters) >= 5:
            clean = "".join("A" if c.isupper() else "B" for c in letters)
        else:
            raise ValueError("Not Bacon format")

    if len(clean) % 5 != 0:
        # Truncate to multiple of 5 if close
        clean = clean[: len(clean) - (len(clean) % 5)]

    chunks = [clean[i : i + 5] for i in range(0, len(clean), 5)]
    out = []
    for ch in chunks:
        if ch in BACON_26:
            out.append(BACON_26[ch])
        else:
            raise ValueError("Invalid Bacon chunk")
    return "".join(out).encode("utf-8")


# Decoder registry: list of (name, decode_func)
class Decoder:
    @staticmethod
    def b64(data: bytes) -> bytes:
        import base64
        # Clean whitespace and try standard or urlsafe
        s = data.strip().replace(b"\n", b"").replace(b"\r", b"")
        try:
            return base64.b64decode(s, validate=True)
        except Exception:
            return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))

    @staticmethod
    def b32(data: bytes) -> bytes:
        import base64
        s = data.strip().replace(b"\n", b"").replace(b"\r", b"")
        return base64.b32decode(s, casefold=True)

    @staticmethod
    def b85(data: bytes) -> bytes:
        import base64
        s = data.strip()
        try:
            return base64.b85decode(s)
        except Exception:
            return base64.a85decode(s)

    @staticmethod
    def b58(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict").strip()
        return decode_base58(s)

    @staticmethod
    def hex(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict").strip()
        # Remove 0x prefixes if present
        s = re.sub(r"\b0x", "", s, flags=re.IGNORECASE)
        s = re.sub(r"[\s,:]+", "", s)
        if not s or len(s) % 2 != 0:
            raise ValueError("Invalid hex length")
        return bytes.fromhex(s)

    @staticmethod
    def binary(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict").strip()
        # Accept "01100110 01101100..." or "0110011001101100..."
        s = re.sub(r"\s+", "", s)
        if len(s) % 8 != 0 or not set(s).issubset({"0", "1"}):
            raise ValueError("Invalid binary bitstream")
        return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))

    @staticmethod
    def octal(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict").strip()
        # Split by spaces or backslashes
        tokens = [t for t in re.split(r"[\s\\]+", s) if t]
        if not tokens or not all(re.match(r"^[0-7]{1,3}$", t) for t in tokens):
            raise ValueError("Invalid octal tokens")
        return bytes(int(t, 8) for t in tokens)

    @staticmethod
    def decimal(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict").strip()
        tokens = [t for t in re.split(r"[\s,]+", s) if t]
        if len(tokens) < 2 or not all(t.isdigit() and 0 <= int(t) <= 255 for t in tokens):
            raise ValueError("Invalid decimal byte list")
        return bytes(int(t) for t in tokens)

    @staticmethod
    def url(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict")
        if "%" not in s:
            raise ValueError("No URL escapes")
        res = urllib.parse.unquote_to_bytes(s)
        if res == data:
            raise ValueError("No change")
        return res

    @staticmethod
    def morse(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict")
        return decode_morse(s)

    @staticmethod
    def rot13(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict")
        res = codecs.decode(s, "rot_13")
        if res == s:
            raise ValueError("No change")
        return res.encode("utf-8")

    @staticmethod
    def rot47(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict")
        return decode_rot47(s)

    @staticmethod
    def bacon(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict")
        return decode_bacon(s)

    @staticmethod
    def html_entities(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict")
        if "&" not in s or ";" not in s:
            raise ValueError("No HTML entities")
        res = html.unescape(s)
        if res == s:
            raise ValueError("No change")
        return res.encode("utf-8")

    @staticmethod
    def unicode_escape(data: bytes) -> bytes:
        s = data.decode("utf-8", errors="strict")
        if "\\u" not in s and "\\x" not in s:
            raise ValueError("No unicode escapes")
        res = codecs.decode(s, "unicode_escape")
        if res == s:
            raise ValueError("No change")
        return res.encode("utf-8")

    @staticmethod
    def reversed_text(data: bytes) -> bytes:
        if len(data) < 4:
            raise ValueError("Too short to reverse")
        return data[::-1]

    @staticmethod
    def zlib_decomp(data: bytes) -> bytes:
        return zlib.decompress(data)

    @staticmethod
    def gzip_decomp(data: bytes) -> bytes:
        return gzip.decompress(data)

    @staticmethod
    def bz2_decomp(data: bytes) -> bytes:
        return bz2.decompress(data)


CONTAINER_DECODERS: list[tuple[str, Callable[[bytes], bytes]]] = [
    ("base64", Decoder.b64),
    ("hex", Decoder.hex),
    ("base32", Decoder.b32),
    ("base58", Decoder.b58),
    ("base85", Decoder.b85),
    ("binary", Decoder.binary),
    ("decimal", Decoder.decimal),
    ("octal", Decoder.octal),
    ("url", Decoder.url),
    ("html", Decoder.html_entities),
    ("unicode_escape", Decoder.unicode_escape),
    ("zlib", Decoder.zlib_decomp),
    ("gzip", Decoder.gzip_decomp),
    ("bz2", Decoder.bz2_decomp),
]

TRANSFORMATION_DECODERS: list[tuple[str, Callable[[bytes], bytes]]] = [
    ("morse", Decoder.morse),
    ("rot13", Decoder.rot13),
    ("rot47", Decoder.rot47),
    ("bacon", Decoder.bacon),
    ("reversed", Decoder.reversed_text),
]

ALL_DECODERS = CONTAINER_DECODERS + TRANSFORMATION_DECODERS


def peel_layers(data: bytes | str, max_depth: int = 5) -> list[tuple[bytes, list[str]]]:
    """Explore and return all discovered unpeeled byte layers: [(data, chain), ...]."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    discovered: list[tuple[bytes, list[str]]] = [(data, [])]
    visited: set[bytes] = {data}
    queue: list[tuple[bytes, list[str], int]] = [(data, [], 0)]

    while queue:
        curr_bytes, chain, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        for name, decode_fn in CONTAINER_DECODERS:
            try:
                decoded = decode_fn(curr_bytes)
                if not decoded or decoded == curr_bytes or decoded in visited:
                    continue
                # Avoid trivial tiny strings
                if len(decoded) < 2 and len(curr_bytes) > 4:
                    continue

                visited.add(decoded)
                new_chain = chain + [name]
                discovered.append((decoded, new_chain))
                queue.append((decoded, new_chain, depth + 1))
            except Exception:
                continue

    return discovered


def peel(
    data: bytes | str,
    max_depth: int = 10,
    flag_patterns: Sequence[str] | None = None,
) -> list[Candidate]:
    """Repeatedly detects and decodes layers of encodings, returning discovered candidates."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    results: list[Candidate] = []
    layers = peel_layers(data, max_depth=max_depth)

    for layer_bytes, chain in layers:
        method_str = " -> ".join(chain) if chain else "raw_input"
        c_score = score(layer_bytes, custom_flag_patterns=flag_patterns)
        results.append(Candidate(plaintext=layer_bytes, method=method_str, params={"chain": chain}, score=c_score))

        # Also test one-shot transformations on this layer
        for t_name, t_fn in TRANSFORMATION_DECODERS:
            try:
                transformed = t_fn(layer_bytes)
                if transformed and transformed != layer_bytes:
                    t_chain = chain + [t_name]
                    t_score = score(transformed, custom_flag_patterns=flag_patterns)
                    results.append(
                        Candidate(
                            plaintext=transformed,
                            method=" -> ".join(t_chain),
                            params={"chain": t_chain},
                            score=t_score,
                        )
                    )
            except Exception:
                continue

    return rank(results, top=10, custom_flag_patterns=flag_patterns)
