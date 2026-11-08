"""Pollard's p-1 and Pollard's rho factorization attacks."""

from __future__ import annotations

import math
from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import gcd, long_to_bytes, modinv


class PollardP1Attack(Attack):
    name = "pollard_p1"

    def applicable(self, n: int | None = None, **ctx: Any) -> bool:
        return n is not None and n > 3

    def factor(self, n: int, b1: int = 150_000) -> tuple[int, int] | None:
        """Pollard's p-1 factorization when p-1 has only small prime factors."""
        a = 2
        for j in range(2, b1):
            a = pow(a, j, n)
            g = gcd(a - 1, n)
            if 1 < g < n:
                return g, n // g
            if g == n:
                break
        return None

    def run(self, n: int, e: int = 65537, c: int | None = None, b1: int = 150_000, **ctx: Any) -> list[Candidate]:
        res = self.factor(n, b1=b1)
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
                candidates.append(Candidate(plaintext=pt, method="rsa_pollard_p1", params=params, score=score(pt)))
            except Exception:
                pass

        if not candidates:
            candidates.append(Candidate(plaintext=b"", method="rsa_pollard_p1", params=params, score=0.0))
        return candidates


class PollardRhoAttack(Attack):
    name = "pollard_rho"

    def applicable(self, n: int | None = None, **ctx: Any) -> bool:
        return n is not None and n > 3

    def factor(self, n: int, max_steps: int = 150_000) -> tuple[int, int] | None:
        """Pollard's rho cycle finding algorithm for integer factorization."""
        for c_const in (1, 3, 5):
            x = 2
            y = 2
            d = 1
            f = lambda val: (val * val + c_const) % n

            for _ in range(max_steps):
                x = f(x)
                y = f(f(y))
                d = gcd(abs(x - y), n)
                if 1 < d < n:
                    return d, n // d
                if d == n:
                    break
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
                candidates.append(Candidate(plaintext=pt, method="rsa_pollard_rho", params=params, score=score(pt)))
            except Exception:
                pass

        if not candidates:
            candidates.append(Candidate(plaintext=b"", method="rsa_pollard_rho", params=params, score=0.0))
        return candidates
