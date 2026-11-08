"""FactorDB lookup attack for RSA."""

from __future__ import annotations

from typing import Any
import requests

from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score
from cryptokit.utils import long_to_bytes, modinv


class FactorDBAttack(Attack):
    name = "factordb"

    def applicable(self, n: int | None = None, offline: bool = False, **ctx: Any) -> bool:
        return n is not None and n > 3 and not offline

    def run(self, n: int, e: int = 65537, c: int | None = None, offline: bool = False, timeout: float = 3.0, **ctx: Any) -> list[Candidate]:
        if offline:
            return []

        try:
            url = f"http://factordb.com/api?query={n}"
            resp = requests.get(url, timeout=timeout)
            if resp.status_code != 200:
                return []
            data = resp.json()
            status = data.get("status")
            # FF = Fully Factored, CF = Composite Factored
            if status not in ("FF", "CF"):
                return []

            raw_factors = data.get("factors", [])
            factors: list[int] = []
            for f_val, count in raw_factors:
                for _ in range(count):
                    factors.append(int(f_val))

            if len(factors) < 2:
                return []

            # Compute phi
            phi = 1
            for p in factors:
                phi *= (p - 1)

            params: dict[str, Any] = {"factors": factors, "phi": phi}
            candidates: list[Candidate] = []
            if c is not None:
                try:
                    d = modinv(e, phi)
                    params["d"] = d
                    m = pow(c, d, n)
                    pt = long_to_bytes(m)
                    candidates.append(Candidate(plaintext=pt, method="rsa_factordb", params=params, score=score(pt)))
                except Exception:
                    pass

            if not candidates:
                candidates.append(Candidate(plaintext=b"", method="rsa_factordb", params=params, score=0.0))
            return candidates
        except Exception:
            return []
