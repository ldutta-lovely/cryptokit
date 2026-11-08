"""Direct RSA decryption when private components (d, p/q, or phi) are known."""

from __future__ import annotations

from typing import Any

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import long_to_bytes, modinv


class DirectRSADecrypt(Attack):
    name = "direct"

    def applicable(
        self,
        c: int | None = None,
        n: int | None = None,
        d: int | None = None,
        p: int | None = None,
        q: int | None = None,
        phi: int | None = None,
        **ctx: Any,
    ) -> bool:
        if c is None or n is None:
            return False
        return (d is not None) or (p is not None and q is not None) or (phi is not None)

    def run(
        self,
        c: int,
        n: int,
        e: int = 65537,
        d: int | None = None,
        p: int | None = None,
        q: int | None = None,
        phi: int | None = None,
        **ctx: Any,
    ) -> list[Candidate]:
        if d is None:
            if phi is None and p is not None and q is not None:
                phi = (p - 1) * (q - 1)
            if phi is not None:
                try:
                    d = modinv(e, phi)
                except Exception:
                    return []

        if d is None:
            return []

        m = pow(c, d, n)
        pt = long_to_bytes(m)
        params = {"d": d, "n": n, "e": e}
        if p is not None:
            params["p"] = p
        if q is not None:
            params["q"] = q
        if phi is not None:
            params["phi"] = phi

        return [Candidate(plaintext=pt, method="rsa_direct", params=params, score=score(pt))]
