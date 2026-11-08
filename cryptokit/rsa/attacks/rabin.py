"""Rabin cryptosystem (e=2) decryption attack."""

from __future__ import annotations

from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import rank, score
from cryptokit.utils import crt, long_to_bytes


class RabinAttack(Attack):
    name = "rabin"

    def applicable(self, c: int | None = None, p: int | None = None, q: int | None = None, **ctx: Any) -> bool:
        return c is not None and p is not None and q is not None and p > 2 and q > 2

    def run(self, c: int, p: int, q: int, n: int | None = None, **ctx: Any) -> list[Candidate]:
        if n is None:
            n = p * q

        # Compute square roots mod p and mod q (assuming p, q = 3 mod 4)
        if p % 4 == 3:
            mp = pow(c, (p + 1) // 4, p)
        else:
            return []

        if q % 4 == 3:
            mq = pow(c, (q + 1) // 4, q)
        else:
            return []

        candidates: list[Candidate] = []
        # Four combinations of square roots: (+/- mp, +/- mq)
        signs = [(mp, mq), (mp, -mq % q), (-mp % p, mq), (-mp % p, -mq % q)]
        for r_p, r_q in signs:
            try:
                m = crt([r_p, r_q], [p, q])
                pt = long_to_bytes(m)
                candidates.append(
                    Candidate(
                        plaintext=pt,
                        method="rabin_decrypt",
                        params={"p": p, "q": q, "root": m},
                        score=score(pt),
                    )
                )
            except Exception:
                continue

        return rank(candidates, top=4)
