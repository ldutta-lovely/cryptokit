"""Tests for cryptokit.scoring."""

from cryptokit.base import Candidate
from cryptokit.scoring import score, rank, calculate_entropy, printable_ratio


def test_entropy_and_printable_ratio():
    assert printable_ratio(b"Hello world!") == 1.0
    assert printable_ratio(b"\x00\x01\x02\x03") == 0.0

    # Low entropy: repeated byte
    assert calculate_entropy(b"AAAAAAA") == 0.0
    # Higher entropy: random distribution
    import os
    rnd = os.urandom(1000)
    assert calculate_entropy(rnd) > 7.0


def test_flag_detection():
    flag_bytes = b"Congratulations! The flag is flag{quick_brown_fox_1337}!"
    s = score(flag_bytes)
    assert s > 1500.0

    # Custom flag format
    custom_bytes = b"Solved: MyOrg{special_token_99}"
    assert score(custom_bytes, custom_flag_patterns=[r"MyOrg\{[^\}]+\}"]) > 1500.0


def test_english_vs_garbage():
    english = b"This is a perfectly legible English sentence describing cryptography principles."
    garbage = bytes(range(256))

    score_eng = score(english)
    score_gar = score(garbage)

    assert score_eng > 100.0
    assert score_gar < 0.0


def test_rank_candidates():
    candidates = [
        Candidate(plaintext=b"\x00\x11\x22\x33\x44", method="random"),
        Candidate(plaintext=b"flag{found_it_first}", method="winning_attack"),
        Candidate(plaintext=b"the quick brown fox jumps over the lazy dog", method="caesar"),
    ]

    ranked = rank(candidates, top=2)
    assert len(ranked) == 2
    assert ranked[0].method == "winning_attack"
    assert ranked[1].method == "caesar"
    assert ranked[0].score > ranked[1].score
