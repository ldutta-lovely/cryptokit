"""Fermat factorization attack for close RSA primes."""

from __future__ import annotations

import math
from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import iroot, long_to_bytes, modinv


class FermatAttack(Attack):
    name = "fermat"

    def applicable(self, n: int | None = None, **ctx: Any) -> bool:
        return n is not None and n > 3

    def factor(self, n: int, max_steps: int = 150_000) -> tuple[int, int] | None:
        """Fermat's difference-of-squares factorization: n = a^2 - b^2 = (a-b)(a+b)."""
        a = math.isqrt(n)
        if a * a < n:
            a += 1

        for _ in range(max_steps):
            b2 = a * a - n
            b, is_exact = iroot(b2, 2)
            if is_exact:
                p = a - b
                q = a + b
                if 1 < p < n:
                    return p, q
            a += 1
        return None

    def run(self, n: int, e: int = 65537, c: int | None = None, max_steps: int = 150_000, **ctx: Any) -> list[Candidate]:
        res = self.factor(n, max_steps=max_steps)
        if not res:
            return []
        p, q = res
        phi = (p - 1) * (q - 1)
        params: dict[str, Any] = {"p": p, "q": q, "phi": phi}

        candidates: list[Candidate] = []
        if c is not None:
            try:
                d = modinv(e, phi)
                params["d"] = d
                m = pow(c, d, n)
                pt = long_to_bytes(m)
                candidates.append(Candidate(plaintext=pt, method="rsa_fermat", params=params, score=score(pt)))
            except Exception:
                pass

        if not candidates:
            candidates.append(Candidate(plaintext=b"", method="rsa_fermat", params=params, score=0.0))
        return candidates
