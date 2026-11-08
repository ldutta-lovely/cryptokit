"""Wiener's attack on RSA with small private exponent d < (1/3) * n^(1/4)."""

from __future__ import annotations

import math
from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import convergents, iroot, long_to_bytes, modinv


class WienerAttack(Attack):
    name = "wiener"

    def applicable(self, n: int | None = None, e: int | None = None, **ctx: Any) -> bool:
        return n is not None and e is not None and n > 3 and e > 1

    def factor(self, n: int, e: int) -> tuple[int, int, int] | None:
        """Find (d, p, q) using Wiener's continued fractions theorem."""
        for k, d in convergents(e, n):
            if k == 0:
                continue
            if (e * d - 1) % k != 0:
                continue

            phi = (e * d - 1) // k
            # x^2 - ((n - phi) + 1)x + n = 0
            b = (n - phi) + 1
            discr = b * b - 4 * n
            if discr < 0:
                continue

            r, is_exact = iroot(discr, 2)
            if not is_exact:
                continue

            if (b + r) % 2 != 0:
                continue

            p = (b + r) // 2
            q = (b - r) // 2
            if p * q == n and 1 < p < n:
                return d, p, q
        return None

    def run(self, n: int, e: int, c: int | None = None, **ctx: Any) -> list[Candidate]:
        res = self.factor(n, e)
        if not res:
            return []
        d, p, q = res
        phi = (p - 1) * (q - 1)
        params: dict[str, Any] = {"d": d, "p": p, "q": q, "phi": phi}

        candidates: list[Candidate] = []
        if c is not None:
            m = pow(c, d, n)
            pt = long_to_bytes(m)
            candidates.append(Candidate(plaintext=pt, method="rsa_wiener", params=params, score=score(pt)))

        if not candidates:
            candidates.append(Candidate(plaintext=b"", method="rsa_wiener", params=params, score=0.0))
        return candidates
