"""Classical cipher cryptanalysis module: Caesar, Atbash, Affine, Rail Fence, Columnar, Scytale, Vigenere, Substitution, Autokey, Beaufort."""

from __future__ import annotations

import collections
import itertools
import math
import random
import re
import string
import time
from typing import Any, Sequence

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import rank, score, ENGLISH_FREQ
from cryptokit.utils import modinv

# Core English quadgrams with logarithmic probabilities
# Pre-computed from standard English corpus for offline simulated annealing
ENGLISH_QUADGRAMS: dict[str, float] = {
    "TION": -2.31, "NTHE": -2.48, "THER": -2.52, "THAT": -2.56, "OFTH": -2.59,
    "FTHE": -2.62, "THES": -2.67, "WITH": -2.71, "INTH": -2.73, "ATIO": -2.76,
    "OFT": -2.80, "HERE": -2.82, "OULD": -2.85, "IGHT": -2.88, "HAVE": -2.90,
    "HICH": -2.91, "WHIC": -2.92, "THIS": -2.94, "THIN": -2.95, "THEY": -2.97,
    "ATTH": -2.98, "EVER": -2.99, "FROM": -3.01, "OTHE": -3.02, "WERE": -3.04,
    "THEM": -3.05, "MENT": -3.07, "SOME": -3.08, "THOU": -3.10, "WILL": -3.12,
    "STHE": -3.13, "THRO": -3.15, "PRES": -3.16, "COMM": -3.18, "EVEN": -3.19,
    "BECA": -3.20, "ECAU": -3.21, "CAUS": -3.22, "AUSE": -3.23, "VERY": -3.25,
    "THIN": -3.26, "WHOS": -3.27, "PEOP": -3.28, "EOPL": -3.29, "OPLE": -3.30,
    "WHAT": -3.31, "SAID": -3.32, "TIME": -3.34, "THIR": -3.35, "MORE": -3.36,
    "THOU": -3.38, "COUL": -3.39, "STAT": -3.40, "GENE": -3.42, "INTE": -3.43,
    "NTER": -3.44, "TERE": -3.45, "REST": -3.46, "ESTI": -3.47, "STIN": -3.48,
    "TING": -3.49, "CONS": -3.50, "ONST": -3.51, "NSTA": -3.52, "STAN": -3.53,
    "TAND": -3.54, "ANDI": -3.55, "NDIN": -3.56, "DING": -3.57, "GOVE": -3.58,
    "OVER": -3.59, "VERN": -3.60, "ERNE": -3.61, "RNED": -3.62, "FLAG": -3.20,
    "CTFS": -3.50, "CRYP": -3.40, "SECU": -3.45, "PASS": -3.42,
}
DEFAULT_QUADGRAM_FLOOR = -7.5


def quadgram_score(text: str) -> float:
    """Evaluate quadgram log-probability score of an uppercase alphabetic string."""
    clean = [c for c in text.upper() if "A" <= c <= "Z"]
    if len(clean) < 4:
        return -100.0
    total = 0.0
    for i in range(len(clean) - 3):
        q = "".join(clean[i : i + 4])
        total += ENGLISH_QUADGRAMS.get(q, DEFAULT_QUADGRAM_FLOOR)
    return total


class CaesarAttack(Attack):
    name = "caesar"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) > 0

    def decrypt(self, text: str, shift: int) -> str:
        res = []
        for c in text:
            if "a" <= c <= "z":
                res.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                res.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
            else:
                res.append(c)
        return "".join(res)

    def run(self, data: bytes | str, top: int = 5, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        candidates: list[Candidate] = []

        for shift in range(1, 26):
            pt = self.decrypt(text, shift)
            pt_bytes = pt.encode("utf-8")
            c_score = score(pt_bytes, custom_flag_patterns=flag_patterns)
            candidates.append(
                Candidate(
                    plaintext=pt_bytes,
                    method="caesar",
                    params={"shift": shift},
                    score=c_score,
                )
            )

        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


class AtbashAttack(Attack):
    name = "atbash"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) > 0

    def decrypt(self, text: str) -> str:
        res = []
        for c in text:
            if "a" <= c <= "z":
                res.append(chr(ord("z") - (ord(c) - ord("a"))))
            elif "A" <= c <= "Z":
                res.append(chr(ord("Z") - (ord(c) - ord("A"))))
            else:
                res.append(c)
        return "".join(res)

    def run(self, data: bytes | str, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        pt = self.decrypt(text)
        pt_bytes = pt.encode("utf-8")
        return [Candidate(plaintext=pt_bytes, method="atbash", params={}, score=score(pt_bytes, custom_flag_patterns=flag_patterns))]


class AffineAttack(Attack):
    name = "affine"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) > 0

    def decrypt(self, text: str, a: int, b: int) -> str:
        a_inv = modinv(a, 26)
        res = []
        for c in text:
            if "a" <= c <= "z":
                res.append(chr((a_inv * ((ord(c) - ord("a")) - b)) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                res.append(chr((a_inv * ((ord(c) - ord("A")) - b)) % 26 + ord("A")))
            else:
                res.append(c)
        return "".join(res)

    def run(self, data: bytes | str, top: int = 5, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        coprimes_26 = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        candidates: list[Candidate] = []

        for a in coprimes_26:
            for b in range(26):
                pt = self.decrypt(text, a, b)
                pt_bytes = pt.encode("utf-8")
                c_score = score(pt_bytes, custom_flag_patterns=flag_patterns)
                candidates.append(
                    Candidate(
                        plaintext=pt_bytes,
                        method="affine",
                        params={"a": a, "b": b},
                        score=c_score,
                    )
                )

        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


class RailFenceAttack(Attack):
    name = "rail_fence"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) >= 4

    def decrypt(self, text: str, rails: int) -> str:
        if rails <= 1 or rails >= len(text):
            return text

        # Determine the rail pattern indices
        pattern = []
        rail = 0
        down = True
        for _ in range(len(text)):
            pattern.append(rail)
            if rail == 0:
                down = True
            elif rail == rails - 1:
                down = False
            rail += 1 if down else -1

        # Count how many characters go to each rail
        counts = collections.Counter(pattern)
        rail_chars: dict[int, list[str]] = {}
        idx = 0
        for r in range(rails):
            cnt = counts[r]
            rail_chars[r] = list(text[idx : idx + cnt])
            idx += cnt

        # Reconstruct plaintext
        res = []
        for r in pattern:
            res.append(rail_chars[r].pop(0))
        return "".join(res)

    def run(self, data: bytes | str, top: int = 5, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        candidates: list[Candidate] = []
        max_rails = min(30, max(2, len(text) // 2 + 1))

        for rails in range(2, max_rails):
            pt = self.decrypt(text, rails)
            pt_bytes = pt.encode("utf-8")
            c_score = score(pt_bytes, custom_flag_patterns=flag_patterns)
            candidates.append(
                Candidate(
                    plaintext=pt_bytes,
                    method="rail_fence",
                    params={"rails": rails},
                    score=c_score,
                )
            )

        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


class ScytaleAttack(Attack):
    name = "scytale"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) >= 4

    def decrypt(self, text: str, diameter: int) -> str:
        rows = math.ceil(len(text) / diameter)
        cols = diameter
        matrix = [[""] * cols for _ in range(rows)]
        idx = 0
        for c in range(cols):
            for r in range(rows):
                if idx < len(text):
                    matrix[r][c] = text[idx]
                    idx += 1
        res = []
        for r in range(rows):
            for c in range(cols):
                if matrix[r][c]:
                    res.append(matrix[r][c])
        return "".join(res)

    def run(self, data: bytes | str, top: int = 5, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        candidates: list[Candidate] = []
        for diameter in range(2, min(len(text) // 2 + 1, 30)):
            pt = self.decrypt(text, diameter)
            pt_bytes = pt.encode("utf-8")
            candidates.append(
                Candidate(
                    plaintext=pt_bytes,
                    method="scytale",
                    params={"diameter": diameter},
                    score=score(pt_bytes, custom_flag_patterns=flag_patterns),
                )
            )
        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


class ColumnarTranspositionAttack(Attack):
    name = "columnar_transposition"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) >= 6

    def encrypt(self, text: str, perm: tuple[int, ...]) -> str:
        k = len(perm)
        cols: dict[int, list[str]] = {i: [] for i in range(k)}
        for idx, char in enumerate(text):
            cols[idx % k].append(char)
        res = []
        for col_idx in perm:
            res.extend(cols[col_idx])
        return "".join(res)

    def decrypt(self, text: str, perm: tuple[int, ...]) -> str:
        k = len(perm)
        rows = math.ceil(len(text) / k)
        # Length of each column
        full_cols = len(text) % k
        col_lens = [rows if full_cols == 0 or i < full_cols else rows - 1 for i in range(k)]

        # Map permutation to column slices
        cols: dict[int, list[str]] = {}
        idx = 0
        for col_idx in perm:
            length = col_lens[col_idx]
            cols[col_idx] = list(text[idx : idx + length])
            idx += length

        res = []
        for r in range(rows):
            for c in range(k):
                if cols[c]:
                    res.append(cols[c].pop(0))
        return "".join(res)

    def run(self, data: bytes | str, max_key_len: int = 6, top: int = 5, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        candidates: list[Candidate] = []

        for k in range(2, min(max_key_len + 1, 7)):
            perms = list(itertools.permutations(range(k)))
            for p in perms:
                pt = self.decrypt(text, p)
                pt_bytes = pt.encode("utf-8")
                c_score = score(pt_bytes, custom_flag_patterns=flag_patterns)
                candidates.append(
                    Candidate(
                        plaintext=pt_bytes,
                        method="columnar_transposition",
                        params={"keysize": k, "permutation": p},
                        score=c_score,
                    )
                )

        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


class VigenereAttack(Attack):
    name = "vigenere"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) > 0

    def decrypt(self, text: str, key: str) -> str:
        key = key.upper()
        if not key:
            return text
        res = []
        ki = 0
        for c in text:
            if "a" <= c <= "z":
                shift = ord(key[ki % len(key)]) - ord("A")
                res.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
                ki += 1
            elif "A" <= c <= "Z":
                shift = ord(key[ki % len(key)]) - ord("A")
                res.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
                ki += 1
            else:
                res.append(c)
        return "".join(res)

    def index_of_coincidence(self, letters: str) -> float:
        n = len(letters)
        if n <= 1:
            return 0.0
        counts = collections.Counter(letters)
        return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))

    def estimate_key_lengths(self, text: str, max_key_len: int = 20, top: int = 4) -> list[int]:
        letters = [c.upper() for c in text if c.isalpha()]
        if len(letters) < 10:
            return list(range(1, min(len(letters), max_key_len) + 1))

        scores = []
        for k in range(1, max_key_len + 1):
            iocs = []
            for col in range(k):
                col_letters = letters[col::k]
                iocs.append(self.index_of_coincidence("".join(col_letters)))
            avg_ioc = sum(iocs) / len(iocs)
            scores.append((abs(avg_ioc - 0.067), k))

        scores.sort(key=lambda x: x[0])
        # Always include small common lengths (2..6) alongside top IoC estimates
        res_keys = [k for _, k in scores[:top]]
        for small_k in [2, 3, 4, 5, 6]:
            if small_k not in res_keys:
                res_keys.append(small_k)
        return res_keys

    def solve_key_for_length(self, text: str, key_len: int) -> str:
        letters = [c.upper() for c in text if c.isalpha()]
        key_chars = []
        for col in range(key_len):
            col_letters = letters[col::key_len]
            counts = collections.Counter(col_letters)
            best_shift = 0
            best_score = -999999.0
            for shift in range(26):
                sc = sum(
                    cnt * ENGLISH_FREQ.get(chr((ord(char) - ord("A") - shift) % 26 + ord("A")), 0.0)
                    for char, cnt in counts.items()
                )
                if sc > best_score:
                    best_score = sc
                    best_shift = shift
            key_chars.append(chr(best_shift + ord("A")))
        return "".join(key_chars)

    def run(
        self,
        data: bytes | str,
        crib: str | None = None,
        key: str | None = None,
        max_key_len: int = 20,
        top: int = 5,
        flag_patterns: Sequence[str] | None = None,
        **ctx: Any,
    ) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        candidates: list[Candidate] = []

        if key:
            pt = self.decrypt(text, key)
            pt_bytes = pt.encode("utf-8")
            return [Candidate(plaintext=pt_bytes, method="vigenere", params={"key": key}, score=score(pt_bytes, custom_flag_patterns=flag_patterns))]

        # If known crib given (e.g. "flag{"), slide across text
        if crib:
            crib_letters = [c.upper() for c in crib if c.isalpha()]
            text_letters = [c.upper() for c in text if c.isalpha()]
            crib_len = len(crib_letters)
            if len(text_letters) >= crib_len:
                for pos in range(len(text_letters) - crib_len + 1):
                    deduced_shifts = [(ord(text_letters[pos + j]) - ord(cb)) % 26 for j, cb in enumerate(crib_letters)]
                    for ksize in range(2, max(crib_len + 1, 10)):
                        known_cols: dict[int, int] = {}
                        conflict = False
                        for j, shift in enumerate(deduced_shifts):
                            col = (pos + j) % ksize
                            if col in known_cols and known_cols[col] != shift:
                                conflict = True
                                break
                            known_cols[col] = shift
                        if conflict:
                            continue

                        full_key_shifts = []
                        for col in range(ksize):
                            if col in known_cols:
                                full_key_shifts.append(known_cols[col])
                            else:
                                col_letters = text_letters[col::ksize]
                                counts = collections.Counter(col_letters)
                                b_shift = 0
                                b_score = -1.0
                                for shift in range(26):
                                    sc = sum(
                                        cnt * ENGLISH_FREQ.get(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")), 0.0)
                                        for ch, cnt in counts.items()
                                    )
                                    if sc > b_score:
                                        b_score = sc
                                        b_shift = shift
                                full_key_shifts.append(b_shift)

                        cand_key = "".join(chr(s + ord("A")) for s in full_key_shifts)
                        pt = self.decrypt(text, cand_key)
                        pt_bytes = pt.encode("utf-8")
                        c_sc = score(pt_bytes, custom_flag_patterns=flag_patterns)
                        candidates.append(
                            Candidate(
                                plaintext=pt_bytes,
                                method="vigenere_crib",
                                params={"crib": crib, "deduced_key": cand_key, "pos": pos},
                                score=c_sc,
                            )
                        )

        key_lengths = self.estimate_key_lengths(text, max_key_len=max_key_len, top=4)
        for klen in key_lengths:
            rec_key = self.solve_key_for_length(text, klen)
            pt = self.decrypt(text, rec_key)
            pt_bytes = pt.encode("utf-8")
            candidates.append(
                Candidate(
                    plaintext=pt_bytes,
                    method="vigenere",
                    params={"key": rec_key, "keysize": klen},
                    score=score(pt_bytes, custom_flag_patterns=flag_patterns),
                )
            )

        return rank(candidates, top=top, custom_flag_patterns=flag_patterns)


class MonoalphabeticSubstitutionAttack(Attack):
    name = "substitution"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) >= 20

    def decrypt(self, text: str, key_map: dict[str, str]) -> str:
        res = []
        for c in text:
            if c.upper() in key_map:
                mapped = key_map[c.upper()]
                res.append(mapped.lower() if c.islower() else mapped)
            else:
                res.append(c)
        return "".join(res)

    def run(
        self,
        data: bytes | str,
        iterations: int = 1500,
        restarts: int = 3,
        flag_patterns: Sequence[str] | None = None,
        **ctx: Any,
    ) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        letters = string.ascii_uppercase
        candidates: list[Candidate] = []

        for _ in range(restarts):
            # Start with random alphabet permutation
            current_key = list(letters)
            random.shuffle(current_key)
            key_map = dict(zip(current_key, letters))

            decrypted = self.decrypt(text, key_map)
            best_score = quadgram_score(decrypted)
            best_key = list(current_key)

            for step in range(iterations):
                # Swap two random letters
                i, j = random.sample(range(26), 2)
                candidate_key = list(best_key)
                candidate_key[i], candidate_key[j] = candidate_key[j], candidate_key[i]

                cand_map = dict(zip(candidate_key, letters))
                cand_dec = self.decrypt(text, cand_map)
                cand_score = quadgram_score(cand_dec)

                if cand_score > best_score:
                    best_score = cand_score
                    best_key = candidate_key

            final_map = dict(zip(best_key, letters))
            final_pt = self.decrypt(text, final_map)
            pt_bytes = final_pt.encode("utf-8")
            c_score = score(pt_bytes, custom_flag_patterns=flag_patterns)
            candidates.append(
                Candidate(
                    plaintext=pt_bytes,
                    method="substitution",
                    params={"key_map": final_map},
                    score=c_score,
                )
            )

        return rank(candidates, top=2, custom_flag_patterns=flag_patterns)


class BeaufortAttack(Attack):
    name = "beaufort"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) > 0

    def decrypt(self, text: str, key: str) -> str:
        key = key.upper()
        if not key:
            return text
        res = []
        ki = 0
        for c in text:
            if "a" <= c <= "z":
                k_val = ord(key[ki % len(key)]) - ord("A")
                res.append(chr((k_val - (ord(c) - ord("a"))) % 26 + ord("a")))
                ki += 1
            elif "A" <= c <= "Z":
                k_val = ord(key[ki % len(key)]) - ord("A")
                res.append(chr((k_val - (ord(c) - ord("A"))) % 26 + ord("A")))
                ki += 1
            else:
                res.append(c)
        return "".join(res)

    def run(self, data: bytes | str, key: str, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        pt = self.decrypt(text, key)
        pt_bytes = pt.encode("utf-8")
        return [Candidate(plaintext=pt_bytes, method="beaufort", params={"key": key}, score=score(pt_bytes, custom_flag_patterns=flag_patterns))]


class AutokeyAttack(Attack):
    name = "autokey"

    def applicable(self, data: bytes | str | None = None, **ctx: Any) -> bool:
        return data is not None and len(data) > 0

    def decrypt(self, text: str, primer: str) -> str:
        primer = primer.upper()
        res = []
        key_stream = list(primer)
        ki = 0
        for c in text:
            if "a" <= c <= "z":
                shift = ord(key_stream[ki]) - ord("A")
                p_char = chr((ord(c) - ord("a") - shift) % 26 + ord("a"))
                res.append(p_char)
                key_stream.append(p_char.upper())
                ki += 1
            elif "A" <= c <= "Z":
                shift = ord(key_stream[ki]) - ord("A")
                p_char = chr((ord(c) - ord("A") - shift) % 26 + ord("A"))
                res.append(p_char)
                key_stream.append(p_char.upper())
                ki += 1
            else:
                res.append(c)
        return "".join(res)

    def run(self, data: bytes | str, primer: str, flag_patterns: Sequence[str] | None = None, **ctx: Any) -> list[Candidate]:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        pt = self.decrypt(text, primer)
        pt_bytes = pt.encode("utf-8")
        return [Candidate(plaintext=pt_bytes, method="autokey", params={"primer": primer}, score=score(pt_bytes, custom_flag_patterns=flag_patterns))]
