"""Tests for cryptokit.xor attacks."""

from cryptokit.utils import xor_bytes, xor_repeating, xor_single
from cryptokit.xor import (
    SingleByteXORAttack,
    RepeatingKeyXORAttack,
    KnownPlaintextXORAttack,
    crib_drag,
)


def test_single_byte_xor():
    target = b"flag{single_byte_xor_is_trivial_to_break}"
    key = 0x5A
    ct = xor_single(target, key)

    attack = SingleByteXORAttack()
    assert attack.applicable(data=ct)
    candidates = attack.run(data=ct, top=3)

    assert len(candidates) > 0
    best = candidates[0]
    assert best.plaintext == target
    assert best.params["key"] == key


def test_repeating_key_xor():
    target = (
        b"Cryptography is the practice and study of techniques for secure communication in the presence of adversarial third parties. "
        b"Here is the secret flag: flag{repeating_key_xor_hamming_solved}!"
    )
    key = b"VIBE"
    ct = xor_repeating(target, key)

    attack = RepeatingKeyXORAttack()
    assert attack.applicable(data=ct)
    candidates = attack.run(data=ct, min_size=2, max_size=10, top=5)

    assert len(candidates) > 0
    # One of the candidates should have recovered the text
    found = any(target in c.plaintext for c in candidates)
    assert found


def test_known_plaintext_xor():
    target = b"flag{known_plaintext_crib_recovery_works_like_a_charm}"
    key = b"HERO"
    ct = xor_repeating(target, key)

    attack = KnownPlaintextXORAttack()
    assert attack.applicable(data=ct, crib="flag{")
    candidates = attack.run(data=ct, crib="flag{", top=5)

    assert len(candidates) > 0
    best = candidates[0]
    assert best.plaintext == target


def test_crib_drag_two_time_pad():
    p1 = b"attack at dawn on the northern front"
    p2 = b"defend the flag{reused_key_is_bad}"
    key = b"VERYSECRETKEYTHATISLONGENOUGHTOCOVERBOTH"

    c1 = xor_bytes(p1, key)
    c2 = xor_bytes(p2, key)

    # Drag "flag{"
    results = crib_drag(c1, c2, "flag{")
    assert len(results) > 0
    # At offset 11 of p2 ("defend the flag{..."), dragging "flag{" reveals p1[11:16] ("awn o")
    matching = [r for r in results if r["offset"] == 11 and r["revealed_text"] == "awn o"]
    assert len(matching) > 0
