"""Tests for cryptokit.auto automated solving pipeline."""

import base64
from Crypto.Util.number import getPrime

from cryptokit.auto import AutoSolver
from cryptokit.classical import CaesarAttack
from cryptokit.utils import bytes_to_long, xor_single


def test_auto_solve_encoded_caesar():
    flag = "flag{auto_pipeline_detects_and_solves_layers}"
    # Shift with Caesar (shift 7)
    caesar = CaesarAttack()
    shifted = caesar.decrypt(flag, -7)
    # Hex encode then base64 encode
    hx = shifted.encode().hex().encode()
    b64 = base64.b64encode(hx)

    solver = AutoSolver()
    candidates, diag = solver.solve(b64, top=3)

    assert len(candidates) > 0
    best = candidates[0]
    assert best.plaintext.decode() == flag
    assert "caesar" in best.method.lower()


def test_auto_solve_xor_layer():
    flag = b"flag{xor_wrapped_in_base64_auto_cracked}"
    xored = xor_single(flag, 0x47)
    b64 = base64.b64encode(xored)

    solver = AutoSolver()
    candidates, diag = solver.solve(b64, top=3)

    assert len(candidates) > 0
    best = candidates[0]
    assert best.plaintext == flag
    assert "single_byte_xor" in best.method.lower()


def test_auto_solve_rsa():
    flag = b"flag{auto_solver_rsa_handoff}"
    m = bytes_to_long(flag)
    e = 3
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    c = pow(m, e, n)

    rsa_text = f"n = {n}\ne = {e}\nc = {c}"
    solver = AutoSolver()
    candidates, diag = solver.solve(rsa_text, top=2)

    assert diag["rsa"] is True
    assert len(candidates) > 0
    assert candidates[0].plaintext == flag
