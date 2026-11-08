"""Small public exponent (small e / exact root) RSA attack."""

from __future__ import annotations

from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import iroot, long_to_bytes


class SmallEAttack(Attack):
    name = "small_e"

    def applicable(self, c: int | None = None, e: int | None = None, **ctx: Any) -> bool:
        return c is not None and e is not None and 1 < e <= 17

    def run(self, c: int, e: int = 3, n: int | None = None, max_k: int = 1000, **ctx: Any) -> list[Candidate]:
        candidates: list[Candidate] = []

        # 1. Direct unreduced root: c = m^e
        root, is_exact = iroot(c, e)
        if is_exact:
            pt = long_to_bytes(root)
            candidates.append(Candidate(plaintext=pt, method="rsa_small_e", params={"e": e, "k": 0}, score=score(pt)))
            return candidates

        # 2. Wrapped root: c + k * n = m^e for small k
        if n is not None and max_k > 0:
            for k in range(1, max_k + 1):
                val = c + k * n
                root, is_exact = iroot(val, e)
                if is_exact:
                    pt = long_to_bytes(root)
                    candidates.append(Candidate(plaintext=pt, method="rsa_small_e", params={"e": e, "k": k}, score=score(pt)))
                    break

        return candidates
