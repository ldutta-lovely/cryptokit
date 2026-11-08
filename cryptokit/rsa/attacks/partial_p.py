"""Partial p leakage attack (low bits brute force and optional Sage Coppersmith)."""

from __future__ import annotations

import subprocess
import tempfile
from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import is_sagemath_available, long_to_bytes, modinv


class PartialPAttack(Attack):
    name = "partial_p"

    def applicable(self, n: int | None = None, p_low: int | None = None, k_bits: int | None = None, **ctx: Any) -> bool:
        return n is not None and p_low is not None and k_bits is not None and k_bits > 0

    def run(
        self,
        n: int,
        p_low: int,
        k_bits: int,
        e: int = 65537,
        c: int | None = None,
        max_search: int = 250_000,
        **ctx: Any,
    ) -> list[Candidate]:
        candidates: list[Candidate] = []
        mod = 1 << k_bits

        # 1. Direct brute force over small unknown high bits: p = p_high * 2^k + p_low
        for high in range(max_search):
            candidate_p = (high << k_bits) | p_low
            if candidate_p > 1 and n % candidate_p == 0:
                p = candidate_p
                q = n // p
                phi = (p - 1) * (q - 1)
                params: dict[str, Any] = {"p": p, "q": q, "phi": phi}
                if c is not None:
                    try:
                        d = modinv(e, phi)
                        params["d"] = d
                        m = pow(c, d, n)
                        pt = long_to_bytes(m)
                        candidates.append(Candidate(plaintext=pt, method="rsa_partial_p", params=params, score=score(pt)))
                    except Exception:
                        pass
                if not candidates:
                    candidates.append(Candidate(plaintext=b"", method="rsa_partial_p", params=params, score=0.0))
                return candidates

        # 2. If SageMath is available, run Coppersmith small roots
        if is_sagemath_available() and k_bits >= n.bit_length() // 4:
            try:
                sage_code = f"""
n = {n}
p_low = {p_low}
k = {k_bits}
F.<x> = PolynomialRing(Zmod(n))
f = x * (2^k) + p_low
f = f.monic()
roots = f.small_roots(X=2^(n.nbits()//2 - k), beta=0.45)
if roots:
    print(int(roots[0]))
"""
                proc = subprocess.run(["sage", "-c", sage_code], capture_output=True, text=True, timeout=10)
                out = proc.stdout.strip()
                if out.isdigit():
                    high = int(out)
                    p = (high << k_bits) | p_low
                    if n % p == 0:
                        q = n // p
                        phi = (p - 1) * (q - 1)
                        params = {"p": p, "q": q, "phi": phi}
                        if c is not None:
                            d = modinv(e, phi)
                            params["d"] = d
                            m = pow(c, d, n)
                            pt = long_to_bytes(m)
                            candidates.append(Candidate(plaintext=pt, method="rsa_partial_p_sage", params=params, score=score(pt)))
            except Exception:
                pass

        return candidates
