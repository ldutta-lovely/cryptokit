"""Shared prime GCD attack across multiple RSA moduli."""

from __future__ import annotations

from typing import Any, Sequence

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import gcd, long_to_bytes, modinv


class SharedPrimeAttack(Attack):
    name = "shared_prime"

    def applicable(self, moduli: Sequence[int] | None = None, **ctx: Any) -> bool:
        return moduli is not None and len(moduli) >= 2

    def run(
        self,
        moduli: Sequence[int],
        ciphertexts: Sequence[int] | None = None,
        e: int = 65537,
        **ctx: Any,
    ) -> list[Candidate]:
        candidates: list[Candidate] = []
        n_count = len(moduli)

        for i in range(n_count):
            for j in range(i + 1, n_count):
                n1, n2 = moduli[i], moduli[j]
                g = gcd(n1, n2)
                if 1 < g < n1 and 1 < g < n2:
                    p = g
                    q1 = n1 // p
                    q2 = n2 // p

                    # Decrypt c1 if available
                    if ciphertexts is not None and i < len(ciphertexts):
                        phi1 = (p - 1) * (q1 - 1)
                        try:
                            d1 = modinv(e, phi1)
                            m1 = pow(ciphertexts[i], d1, n1)
                            pt1 = long_to_bytes(m1)
                            candidates.append(
                                Candidate(
                                    plaintext=pt1,
                                    method="rsa_shared_prime",
                                    params={"modulus_idx": i, "p": p, "q": q1, "d": d1},
                                    score=score(pt1),
                                )
                            )
                        except Exception:
                            pass

                    # Decrypt c2 if available
                    if ciphertexts is not None and j < len(ciphertexts):
                        phi2 = (p - 1) * (q2 - 1)
                        try:
                            d2 = modinv(e, phi2)
                            m2 = pow(ciphertexts[j], d2, n2)
                            pt2 = long_to_bytes(m2)
                            candidates.append(
                                Candidate(
                                    plaintext=pt2,
                                    method="rsa_shared_prime",
                                    params={"modulus_idx": j, "p": p, "q": q2, "d": d2},
                                    score=score(pt2),
                                )
                            )
                        except Exception:
                            pass

        return candidates
