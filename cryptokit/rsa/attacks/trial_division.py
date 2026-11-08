"""Trial division attack for RSA."""

from __future__ import annotations

import math
from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import rank, score
from cryptokit.utils import long_to_bytes, modinv


class TrialDivisionAttack(Attack):
    name = "trial_division"

    def applicable(self, n: int | None = None, **ctx: Any) -> bool:
        return n is not None and n > 3

    def factor(self, n: int, limit: int = 2_000_000) -> tuple[int, int] | None:
        """Trial division up to limit."""
        if n % 2 == 0:
            return 2, n // 2
        d = 3
        max_d = min(int(math.isqrt(n)) + 1, limit)
        while d <= max_d:
            if n % d == 0:
                return d, n // d
            d += 2
        return None

    def run(self, n: int, e: int = 65537, c: int | None = None, limit: int = 2_000_000, **ctx: Any) -> list[Candidate]:
        res = self.factor(n, limit=limit)
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
                candidates.append(Candidate(plaintext=pt, method="rsa_trial_division", params=params, score=score(pt)))
            except Exception:
                pass

        if not candidates:
            candidates.append(Candidate(plaintext=b"", method="rsa_trial_division", params=params, score=0.0))
        return candidates
