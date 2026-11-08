"""Common modulus attack for RSA."""

from __future__ import annotations

from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import gcd, long_to_bytes, modinv, xgcd


class CommonModulusAttack(Attack):
    name = "common_modulus"

    def applicable(
        self,
        n: int | None = None,
        e1: int | None = None,
        e2: int | None = None,
        c1: int | None = None,
        c2: int | None = None,
        **ctx: Any,
    ) -> bool:
        return (
            n is not None
            and e1 is not None
            and e2 is not None
            and c1 is not None
            and c2 is not None
            and gcd(e1, e2) == 1
        )

    def run(self, n: int, e1: int, e2: int, c1: int, c2: int, **ctx: Any) -> list[Candidate]:
        g, a, b = xgcd(e1, e2)
        if g != 1:
            return []

        # Handle negative exponents via modular inverse
        if a < 0:
            c1_inv = modinv(c1, n)
            part1 = pow(c1_inv, -a, n)
        else:
            part1 = pow(c1, a, n)

        if b < 0:
            c2_inv = modinv(c2, n)
            part2 = pow(c2_inv, -b, n)
        else:
            part2 = pow(c2, b, n)

        m = (part1 * part2) % n
        pt = long_to_bytes(m)
        params = {"n": n, "e1": e1, "e2": e2, "a": a, "b": b}
        return [Candidate(plaintext=pt, method="rsa_common_modulus", params=params, score=score(pt))]
