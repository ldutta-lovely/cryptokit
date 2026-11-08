"""Multi-prime RSA and non-standard phi decryption attack."""

from __future__ import annotations

import itertools
import math
from typing import Any, Sequence

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import crt, gcd, long_to_bytes, modinv


def modular_eth_roots(c: int, e: int, p: int) -> list[int]:
    """Find all solutions x such that x^e == c (mod p) for prime p."""
    g = gcd(e, p - 1)
    if g == 1:
        d = modinv(e, p - 1)
        return [pow(c, d, p)]

    # If small prime or small number of roots, find by checking candidates
    # c must be an e-th power mod p
    if pow(c, (p - 1) // g, p) != 1:
        return []

    roots = []
    # If p is small enough, brute-force
    if p < 100_000:
        for x in range(p):
            if pow(x, e, p) == c % p:
                roots.append(x)
                if len(roots) == g:
                    break
        return roots

    # Otherwise if g is small (e.g. 2 or 3), try finding generator
    # For general CTFs, standard prime solver
    return []


class MultiPrimeAttack(Attack):
    name = "multiprime"

    def applicable(self, factors: Sequence[int] | None = None, **ctx: Any) -> bool:
        return factors is not None and len(factors) >= 2

    def run(
        self,
        factors: Sequence[int],
        c: int,
        e: int = 65537,
        n: int | None = None,
        **ctx: Any,
    ) -> list[Candidate]:
        candidates: list[Candidate] = []
        if n is None:
            n = 1
            for p in factors:
                n *= p

        # 1. Standard case: gcd(e, phi) == 1
        phi = 1
        for p in factors:
            phi *= (p - 1)

        if gcd(e, phi) == 1:
            try:
                d = modinv(e, phi)
                m = pow(c, d, n)
                pt = long_to_bytes(m)
                params = {"factors": list(factors), "phi": phi, "d": d}
                candidates.append(Candidate(plaintext=pt, method="rsa_multiprime", params=params, score=score(pt)))
                return candidates
            except Exception:
                pass

        # 2. Non-standard case: gcd(e, phi) != 1. Solve e-th roots mod each prime and combine via CRT
        roots_per_prime: list[list[int]] = []
        for p in factors:
            r = modular_eth_roots(c, e, p)
            if not r:
                return candidates
            roots_per_prime.append(r)

        # Try all Cartesian product combinations via CRT
        for comb in itertools.product(*roots_per_prime):
            try:
                m = crt(comb, factors)
                pt = long_to_bytes(m)
                candidates.append(
                    Candidate(
                        plaintext=pt,
                        method="rsa_multiprime_roots",
                        params={"factors": list(factors), "combination": comb},
                        score=score(pt),
                    )
                )
            except Exception:
                continue

        return candidates
