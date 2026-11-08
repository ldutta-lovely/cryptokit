"""Symmetric cryptography analysis and attack module: ECB detection, byte-at-a-time, CBC bit-flip, padding oracle, and AES brute-force."""

from __future__ import annotations

import collections
import hashlib
from typing import Any, Callable, Protocol, Sequence

from Crypto.Cipher import AES

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import rank, score
from cryptokit.utils import chunk_bytes, xor_bytes


class ECBOracle(Protocol):
    """Protocol for byte-at-a-time ECB encryption oracle."""

    def __call__(self, prefix: bytes) -> bytes:
        """Encrypts prefix + secret_suffix using AES-ECB."""
        ...


class PaddingOracle(Protocol):
    """Protocol for CBC padding oracle."""

    def __call__(self, ciphertext: bytes) -> bool:
        """Returns True if ciphertext decrypts with valid PKCS#7 padding; False otherwise."""
        ...


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply standard PKCS#7 padding to data."""
    if block_size < 2 or block_size > 255:
        raise ValueError("Invalid block size for PKCS#7")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Validate and strip PKCS#7 padding.

    Raises ValueError on invalid padding.
    """
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid padding byte value")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def is_pkcs7_padded(data: bytes, block_size: int = 16) -> bool:
    """Return True if data has valid PKCS#7 padding; False otherwise."""
    try:
        pkcs7_unpad(data, block_size)
        return True
    except ValueError:
        return False


def detect_ecb(data: bytes, block_size: int = 16) -> dict[str, Any]:
    """Detect ECB mode by checking for repeated 16-byte blocks."""
    if len(data) < block_size * 2:
        return {"is_ecb": False, "confidence": 0.0, "duplicate_blocks": 0, "total_blocks": 0}

    chunks = chunk_bytes(data[: len(data) - (len(data) % block_size)], block_size)
    total_chunks = len(chunks)
    counts = collections.Counter(chunks)
    duplicates = sum(count - 1 for count in counts.values() if count > 1)

    confidence = duplicates / total_chunks if total_chunks > 0 else 0.0
    return {
        "is_ecb": duplicates > 0,
        "confidence": round(confidence, 3),
        "duplicate_blocks": duplicates,
        "total_blocks": total_chunks,
        "repeats": {chunk.hex(): cnt for chunk, cnt in counts.items() if cnt > 1},
    }


def ecb_byte_at_a_time(oracle: ECBOracle, block_size: int = 16, max_length: int = 256) -> bytes:
    """Decrypt hidden secret suffix using byte-at-a-time ECB attack."""
    # Find base ciphertext length
    base_ct_len = len(oracle(b""))
    recovered = bytearray()

    for idx in range(max_length):
        block_idx = idx // block_size
        pad_len = block_size - 1 - (idx % block_size)
        prefix = b"A" * pad_len

        # Target block from oracle
        target_ct = oracle(prefix)
        target_block = target_ct[block_idx * block_size : (block_idx + 1) * block_size]

        # Dictionary of all possible next bytes
        found_byte = None
        for candidate_byte in range(256):
            test_input = prefix + bytes(recovered) + bytes([candidate_byte])
            test_ct = oracle(test_input)
            test_block = test_ct[block_idx * block_size : (block_idx + 1) * block_size]
            if test_block == target_block:
                found_byte = candidate_byte
                break

        if found_byte is None:
            break

        recovered.append(found_byte)
        # Check if padding byte encountered at end
        if len(recovered) > 1 and recovered[-1] == 1 and is_pkcs7_padded(bytes(recovered), block_size):
            try:
                return pkcs7_unpad(bytes(recovered), block_size)
            except Exception:
                pass

    return bytes(recovered)


def cbc_bit_flip(
    ciphertext: bytes,
    original_plaintext: bytes,
    desired_plaintext: bytes,
    offset: int,
    block_size: int = 16,
) -> bytes:
    """Perform CBC bit-flipping attack to alter plaintext at specified offset.

    Modifies the preceding ciphertext block C_{i-1} using XOR delta.
    """
    if len(original_plaintext) != len(desired_plaintext):
        raise ValueError("Original and desired plaintexts must have equal length")
    if offset < block_size:
        raise ValueError(f"Offset ({offset}) must be at least block_size ({block_size}) to modify preceding block")

    delta = xor_bytes(original_plaintext, desired_plaintext)
    ct_array = bytearray(ciphertext)
    flip_start = offset - block_size

    if flip_start + len(delta) > len(ciphertext):
        raise ValueError("Flip range exceeds ciphertext length")

    for i, d in enumerate(delta):
        ct_array[flip_start + i] ^= d

    return bytes(ct_array)


def cbc_padding_oracle_decrypt(
    ciphertext: bytes,
    oracle: PaddingOracle,
    block_size: int = 16,
) -> bytes:
    """Decrypt ciphertext block-by-block using CBC padding oracle attack."""
    if len(ciphertext) < block_size * 2 or len(ciphertext) % block_size != 0:
        raise ValueError("Ciphertext length must be a multiple of block_size and include IV")

    blocks = chunk_bytes(ciphertext, block_size)
    num_blocks = len(blocks)
    recovered_plaintext = bytearray()

    # Process each block pair: C_{i-1} (IV/prev) and C_i
    for b_idx in range(1, num_blocks):
        prev_block = blocks[b_idx - 1]
        target_block = blocks[b_idx]
        intermediate = bytearray(block_size)

        # Recover bytes from right (pad_val=1) to left (pad_val=block_size)
        for byte_idx in range(block_size - 1, -1, -1):
            pad_val = block_size - byte_idx
            prefix = b"\x00" * byte_idx

            # Prepare suffix for previously found intermediate bytes
            suffix = bytearray()
            for k in range(byte_idx + 1, block_size):
                suffix.append(intermediate[k] ^ pad_val)

            found_int_byte = None
            for guess in range(256):
                # If guess matches current byte in prev_block and pad_val==1, could trigger false positive
                crafted_prev = prefix + bytes([guess]) + suffix
                if oracle(crafted_prev + target_block):
                    if pad_val == 1 and byte_idx > 0:
                        # Extra check to ensure padding is really 0x01
                        check_prefix = bytearray(crafted_prev)
                        check_prefix[0] ^= 1
                        if not oracle(bytes(check_prefix) + target_block):
                            continue
                    found_int_byte = guess ^ pad_val
                    break

            if found_int_byte is None:
                found_int_byte = 0  # Fallback

            intermediate[byte_idx] = found_int_byte

        # Plaintext block is intermediate XOR prev_block
        pt_block = bytes(x ^ y for x, y in zip(intermediate, prev_block))
        recovered_plaintext.extend(pt_block)

    # Attempt to unpad final plaintext
    try:
        return pkcs7_unpad(bytes(recovered_plaintext), block_size)
    except Exception:
        return bytes(recovered_plaintext)


def aes_brute_force(
    ciphertext: bytes,
    wordlist: Sequence[str | bytes],
    mode: str = "ECB",
    iv: bytes | None = None,
    top: int = 5,
    flag_patterns: Sequence[str] | None = None,
) -> list[Candidate]:
    """Brute force AES decryption against a candidate wordlist in ECB or CBC mode."""
    candidates: list[Candidate] = []
    mode_upper = mode.upper()

    for word in wordlist:
        raw_word = word.encode("utf-8") if isinstance(word, str) else word

        # Test key derivations:
        # 1. Direct word padded/truncated to 16 bytes
        # 2. SHA256 of word (32 bytes)
        # 3. MD5 of word (16 bytes)
        # 4. Hex string if valid
        keys: list[tuple[str, bytes]] = [
            ("direct", (raw_word + b"\x00" * 32)[:16]),
            ("sha256", hashlib.sha256(raw_word).digest()),
            ("md5", hashlib.md5(raw_word).digest()),
        ]
        if len(raw_word) in (32, 64):
            try:
                keys.append(("hex", bytes.fromhex(raw_word.decode())))
            except Exception:
                pass

        for key_type, key in keys:
            try:
                if mode_upper == "ECB":
                    cipher = AES.new(key, AES.MODE_ECB)
                    pt = cipher.decrypt(ciphertext)
                elif mode_upper == "CBC":
                    cipher_iv = iv if iv is not None else ciphertext[:16]
                    ct_body = ciphertext if iv is not None else ciphertext[16:]
                    cipher = AES.new(key, AES.MODE_CBC, iv=cipher_iv)
                    pt = cipher.decrypt(ct_body)
                else:
                    continue

                # Strip PKCS#7 if present
                try:
                    pt_clean = pkcs7_unpad(pt)
                except Exception:
                    pt_clean = pt

                c_score = score(pt_clean, custom_flag_patterns=flag_patterns)
                candidates.append(
                    Candidate(
                        plaintext=pt_clean,
                        method=f"aes_{mode.lower()}_bruteforce",
                        params={"password": raw_word.decode("utf-8", errors="replace"), "key_type": key_type, "key_hex": key.hex()},
                        score=c_score,
                    )
                )
            except Exception:
                continue

    return rank(candidates, top=top, custom_flag_patterns=flag_patterns)
