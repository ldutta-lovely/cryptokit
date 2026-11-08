"""XOR cryptanalysis module: single-byte, repeating-key, crib-based, and two-time pad."""

from __future__ import annotations

import itertools
from typing import Any, Sequence

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import rank, score
from cryptokit.utils import xor_bytes, xor_repeating, xor_single


def hamming_distance(b1: bytes, b2: bytes) -> int:
    """Calculate the bitwise Hamming distance (count of differing bits) between two byte strings."""
    return sum((x ^ y).bit_count() for x, y in zip(b1, b2))


class SingleByteXORAttack(Attack):
    name = "single_byte_xor"

    def applicable(self, data: bytes | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) > 0

    def run(self, data: bytes, top: int = 5, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        candidates: list[Candidate] = []
        for key in range(256):
            pt = xor_single(data, key)
            c_score = score(pt, custom_flag_patterns=flag_patterns)
            candidates.append(
                Candidate(
                    plaintext=pt,
                    method="single_byte_xor",
                    params={"key": key, "key_hex": f"0x{key:02x}", "key_char": chr(key) if 32 <= key <= 126 else None},
                    score=c_score,
                )
            )
        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


class RepeatingKeyXORAttack(Attack):
    name = "repeating_key_xor"

    def applicable(self, data: bytes | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) >= 8

    def estimate_keysizes(self, data: bytes, min_size: int = 2, max_size: int = 40, top: int = 5) -> list[int]:
        """Estimate repeating XOR key sizes by computing normalized Hamming distance between blocks."""
        scores: list[tuple[float, int]] = []
        max_k = min(max_size, len(data) // 4)
        if max_k < min_size:
            return list(range(min_size, min(len(data), max_size) + 1))

        for k in range(min_size, max_k + 1):
            distances = []
            num_blocks = min(len(data) // k, 8)
            for i in range(num_blocks - 1):
                b1 = data[i * k : (i + 1) * k]
                b2 = data[(i + 1) * k : (i + 2) * k]
                distances.append(hamming_distance(b1, b2) / k)
            if distances:
                avg_dist = sum(distances) / len(distances)
                scores.append((avg_dist, k))

        scores.sort(key=lambda x: x[0])
        return [k for _, k in scores[:top]]

    def solve_for_keysize(self, data: bytes, keysize: int) -> bytes:
        """Transpose ciphertext into keysize slices and solve each slice as single-byte XOR."""
        from cryptokit.scoring import ENGLISH_FREQ

        key = bytearray(keysize)
        for i in range(keysize):
            slice_bytes = data[i::keysize]
            best_byte = 0
            best_score = -999999.0
            for b in range(256):
                pt = xor_single(slice_bytes, b)
                # Quick column scoring using printable ratio and English letter/space frequencies
                p_ratio = sum(1 for byte in pt if 32 <= byte <= 126 or byte in (9, 10, 13)) / len(pt)
                if p_ratio < 0.7:
                    sc = -1000.0 + (p_ratio * 100.0)
                else:
                    sc = p_ratio * 50.0
                    for byte in pt:
                        ch = chr(byte).upper()
                        if "A" <= ch <= "Z":
                            sc += ENGLISH_FREQ.get(ch, 0.0)
                        elif byte == ord(" "):
                            sc += 15.0
                        elif byte < 32:
                            sc -= 25.0
                if sc > best_score:
                    best_score = sc
                    best_byte = b
            key[i] = best_byte
        return bytes(key)

    def run(
        self,
        data: bytes,
        min_size: int = 2,
        max_size: int = 40,
        top: int = 5,
        flag_patterns: Sequence[str] | None = None,
        **ctx: Any,
    ) -> list[Candidate]:
        candidate_keysizes = self.estimate_keysizes(data, min_size, max_size, top=top)
        candidates: list[Candidate] = []

        for ksize in candidate_keysizes:
            key = self.solve_for_keysize(data, ksize)
            pt = xor_repeating(data, key)
            c_score = score(pt, custom_flag_patterns=flag_patterns)
            candidates.append(
                Candidate(
                    plaintext=pt,
                    method="repeating_key_xor",
                    params={"keysize": ksize, "key": key, "key_repr": key.decode("utf-8", errors="replace")},
                    score=c_score,
                )
            )

        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


class KnownPlaintextXORAttack(Attack):
    name = "known_plaintext_xor"

    def applicable(self, data: bytes | None = None, crib: str | bytes | None = None, **ctx: Any) -> bool:
        return data is not None and crib is not None and len(data) >= len(crib)

    def run(
        self,
        data: bytes,
        crib: str | bytes,
        top: int = 5,
        flag_patterns: Sequence[str] | None = None,
        **ctx: Any,
    ) -> list[Candidate]:
        if isinstance(crib, str):
            crib_bytes = crib.encode("utf-8")
        else:
            crib_bytes = crib

        candidates: list[Candidate] = []
        crib_len = len(crib_bytes)

        # Slide crib across data to find candidate key fragments
        for offset in range(len(data) - crib_len + 1):
            slice_data = data[offset : offset + crib_len]
            candidate_key_fragment = xor_bytes(slice_data, crib_bytes)

            # Check if this fragment could repeat to decrypt the whole data
            for klen in range(1, len(candidate_key_fragment) + 1):
                key = candidate_key_fragment[:klen]
                # Adjust key rotation based on offset
                shift = offset % klen
                rotated_key = key[-shift:] + key[:-shift] if shift else key
                pt = xor_repeating(data, rotated_key)
                c_score = score(pt, custom_flag_patterns=flag_patterns)
                candidates.append(
                    Candidate(
                        plaintext=pt,
                        method="known_plaintext_xor",
                        params={"offset": offset, "key": rotated_key, "key_repr": rotated_key.decode("utf-8", errors="replace")},
                        score=c_score,
                    )
                )

        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


def crib_drag(c1: bytes, c2: bytes, crib: str | bytes) -> list[dict[str, Any]]:
    """Slide a known crib across XOR of two ciphertexts (C1 ^ C2 = P1 ^ P2).

    Reveals what the other plaintext would contain if the crib was present at each position.
    """
    if isinstance(crib, str):
        crib_b = crib.encode("utf-8")
    else:
        crib_b = crib

    c1_xor_c2 = xor_bytes(c1, c2)
    min_len = len(c1_xor_c2)
    crib_len = len(crib_b)

    results = []
    for offset in range(min_len - crib_len + 1):
        segment = c1_xor_c2[offset : offset + crib_len]
        revealed = xor_bytes(segment, crib_b)
        results.append({
            "offset": offset,
            "crib": crib_b,
            "revealed_bytes": revealed,
            "revealed_text": revealed.decode("utf-8", errors="replace"),
            "score": score(revealed),
        })

    results.sort(key=lambda x: x["score"], reverse=True)
    return results
