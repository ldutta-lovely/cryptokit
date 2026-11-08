"""Candidate scoring module for ranking decrypted outputs and flags."""

from __future__ import annotations

import collections
import math
import re
from typing import Sequence

from cryptokit.base import Candidate

# Common CTF flag regex patterns (case-insensitive flag matching)
DEFAULT_FLAG_PATTERNS = [
    r"flag\{[^\}\n]+\}",
    r"ctf\{[^\}\n]+\}",
    r"picoCTF\{[^\}\n]+\}",
    r"HTB\{[^\}\n]+\}",
    r"crypto\{[^\}\n]+\}",
    r"sec\{[^\}\n]+\}",
    r"FLAG\{[^\}\n]+\}",
]

# Standard English letter frequencies (percentage 0..100)
ENGLISH_FREQ: dict[str, float] = {
    "A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702,
    "F": 2.228, "G": 2.015, "H": 6.094, "I": 6.966, "J": 0.153,
    "K": 0.772, "L": 4.025, "M": 2.406, "N": 6.749, "O": 7.507,
    "P": 1.929, "Q": 0.095, "R": 5.987, "S": 6.327, "T": 9.056,
    "U": 2.758, "V": 0.978, "W": 2.360, "X": 0.150, "Y": 1.974,
    "Z": 0.074,
}

COMMON_BIGRAMS = {
    "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
    "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
    "ST", "TO", "NT", "HA", "OU", "EA",
}

COMMON_TRIGRAMS = {
    "THE", "AND", "ING", "ENT", "ION", "HER", "FOR", "THA", "NTH", "INT",
    "ERE", "TIO", "TER", "EST", "ERS", "ATI", "HAT", "ATE", "ALL", "ETH",
}

PRINTABLE_BYTES = set(range(32, 127)) | {9, 10, 13}  # include \t, \n, \r


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    """Calculate ratio of printable ASCII bytes (0.0 to 1.0)."""
    if not data:
        return 0.0
    printable_count = sum(1 for b in data if b in PRINTABLE_BYTES)
    return printable_count / len(data)


def chi_squared_english(text_upper: str) -> float:
    """Calculate Chi-squared statistic against English letter frequencies."""
    letters = [c for c in text_upper if "A" <= c <= "Z"]
    total_letters = len(letters)
    if total_letters < 5:
        return 999.0

    counts = collections.Counter(letters)
    chi2 = 0.0
    for char, expected_pct in ENGLISH_FREQ.items():
        expected_count = (expected_pct / 100.0) * total_letters
        observed_count = counts.get(char, 0)
        chi2 += ((observed_count - expected_count) ** 2) / expected_count
    return chi2


def score(data: bytes, custom_flag_patterns: Sequence[str] | None = None) -> float:
    """Score a byte sequence for CTF cryptanalysis value.

    Higher scores indicate higher likelihood of being the plaintext or containing a flag.
    Returns a float score.
    """
    if not data:
        return -1000.0

    total_len = len(data)
    p_ratio = printable_ratio(data)

    # Heavy penalty for completely non-printable binary
    if p_ratio < 0.2:
        return -500.0 + (p_ratio * 100.0)

    # Base score derived from printable ratio (0 to 100)
    current_score = p_ratio * 100.0

    # Penalize non-whitespace control characters (< 32, not \t, \n, \r)
    control_count = sum(1 for b in data if b < 32 and b not in (9, 10, 13))
    current_score -= control_count * 15.0

    # Convert to decoded string for textual analysis
    text = data.decode("utf-8", errors="replace")
    text_upper = text.upper()

    # 1. Flag format match: massive bonus
    patterns = list(DEFAULT_FLAG_PATTERNS)
    if custom_flag_patterns:
        patterns.extend(custom_flag_patterns)

    found_flags = 0
    for pat in patterns:
        try:
            matches = re.findall(pat, text, flags=re.IGNORECASE)
            if matches:
                found_flags += len(matches)
        except re.error:
            continue

    if found_flags > 0:
        current_score += 1500.0 * found_flags

    # 2. English frequency analysis
    chi2 = chi_squared_english(text_upper)
    # Chi-squared: lower is better; map to 0..150 bonus
    if chi2 < 20.0:
        current_score += 150.0
    elif chi2 < 45.0:
        current_score += 100.0
    elif chi2 < 100.0:
        current_score += 50.0
    elif chi2 < 250.0:
        current_score += 20.0

    # 3. N-gram bonuses
    if len(text_upper) >= 2:
        bigram_hits = sum(1 for i in range(len(text_upper) - 1) if text_upper[i : i + 2] in COMMON_BIGRAMS)
        current_score += min(bigram_hits * 4.0, 100.0)

    if len(text_upper) >= 3:
        trigram_hits = sum(1 for i in range(len(text_upper) - 2) if text_upper[i : i + 3] in COMMON_TRIGRAMS)
        current_score += min(trigram_hits * 8.0, 120.0)

    # 4. Entropy adjustment: English text is typically between 3.5 and 5.0
    entropy = calculate_entropy(data)
    if 3.2 <= entropy <= 5.2 and p_ratio > 0.85:
        current_score += 50.0
    elif entropy > 7.0:
        current_score -= (entropy - 7.0) * 100.0

    return round(current_score, 2)


def rank(
    candidates: Sequence[Candidate],
    top: int = 5,
    custom_flag_patterns: Sequence[str] | None = None,
) -> list[Candidate]:
    """Score, deduplicate, and sort candidates by score in descending order."""
    if not candidates:
        return []

    scored_candidates: list[Candidate] = []
    seen_plaintexts: set[bytes] = set()

    for cand in candidates:
        if cand.plaintext in seen_plaintexts:
            continue
        seen_plaintexts.add(cand.plaintext)
        cand_score = score(cand.plaintext, custom_flag_patterns=custom_flag_patterns)
        cand.score = cand_score
        scored_candidates.append(cand)

    scored_candidates.sort(key=lambda c: c.score, reverse=True)
    return scored_candidates[:top]
