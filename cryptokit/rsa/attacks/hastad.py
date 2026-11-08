"""Hastad's broadcast attack for RSA using CRT and integer root."""

from __future__ import annotations

from typing import Any, Sequence

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import crt, iroot, long_to_bytes


class HastadAttack(Attack):
    name = "hastad"

    def applicable(
        self,
        e: int | None = None,
        moduli: Sequence[int] | None = None,
        ciphertexts: Sequence[int] | None = None,
        **ctx: Any,
    ) -> bool:
        return (
            e is not None
            and moduli is not None
            and ciphertexts is not None
            and len(moduli) == len(ciphertexts)
            and len(moduli) >= e
        )

    def run(
        self,
        e: int,
        moduli: Sequence[int],
        ciphertexts: Sequence[int],
        **ctx: Any,
    ) -> list[Candidate]:
        if len(moduli) < e or len(ciphertexts) < e:
            return []

        # Take the first e moduli and ciphertexts
        m_list = list(moduli[:e])
        c_list = list(ciphertexts[:e])

        try:
            c_combined = crt(c_list, m_list)
            root, is_exact = iroot(c_combined, e)
            if is_exact:
                pt = long_to_bytes(root)
                return [
                    Candidate(
                        plaintext=pt,
                        method="rsa_hastad",
                        params={"e": e, "num_moduli": e},
                        score=score(pt),
                    )
                ]
        except Exception:
            pass

        return []
