"""RSA unified attack runner, parameter parser, and PEM exporter."""

from __future__ import annotations

import ast
import concurrent.futures
import json
import re
from typing import Any, Sequence

from Crypto.PublicKey import RSA

from cryptokit.base import Candidate
from cryptokit.scoring import rank, score
from cryptokit.utils import long_to_bytes, modinv

# Import all attack implementations
from cryptokit.rsa.attacks.trial_division import TrialDivisionAttack
from cryptokit.rsa.attacks.factordb import FactorDBAttack
from cryptokit.rsa.attacks.fermat import FermatAttack
from cryptokit.rsa.attacks.pollard import PollardP1Attack, PollardRhoAttack
from cryptokit.rsa.attacks.small_e import SmallEAttack
from cryptokit.rsa.attacks.wiener import WienerAttack
from cryptokit.rsa.attacks.common_modulus import CommonModulusAttack
from cryptokit.rsa.attacks.hastad import HastadAttack
from cryptokit.rsa.attacks.shared_prime import SharedPrimeAttack
from cryptokit.rsa.attacks.partial_p import PartialPAttack
from cryptokit.rsa.attacks.multiprime import MultiPrimeAttack
from cryptokit.rsa.attacks.direct import DirectRSADecrypt
from cryptokit.rsa.attacks.rabin import RabinAttack


def parse_rsa_params(raw_text_or_dict: str | dict[str, Any]) -> dict[str, Any]:
    """Parse RSA parameters from JSON, key=val definitions, PEM, or dictionary."""
    if isinstance(raw_text_or_dict, dict):
        return raw_text_or_dict

    text = raw_text_or_dict.strip()

    # 1. Check if PEM
    if "-----BEGIN" in text:
        try:
            key = RSA.import_key(text)
            params: dict[str, Any] = {"n": key.n, "e": key.e}
            if key.has_private():
                params["d"] = key.d
                params["p"] = key.p
                params["q"] = key.q
            return params
        except Exception:
            pass

    # 2. Check if JSON
    if text.startswith("{") and text.endswith("}"):
        try:
            data = json.loads(text)
            # Convert string hex or dec numbers to int
            parsed = {}
            for k, v in data.items():
                if isinstance(v, str):
                    v_str = v.strip()
                    parsed[k] = int(v_str, 16) if v_str.startswith("0x") else int(v_str)
                else:
                    parsed[k] = v
            return parsed
        except Exception:
            pass

    # 3. Regex parser for "n = ...", "e = ...", "c = ..."
    parsed_params: dict[str, Any] = {}
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Match variable assignment: var = val
        m = re.match(r"^([a-zA-Z0-9_]+)\s*[:=]\s*(.+)$", line)
        if m:
            var_name = m.group(1).lower()
            val_str = m.group(2).strip().rstrip(",;")

            # Handle list literals: e.g. n = [0x12, 0x34]
            if val_str.startswith("[") and val_str.endswith("]"):
                try:
                    parsed_params[var_name] = ast.literal_eval(val_str)
                    continue
                except Exception:
                    pass

            # Handle hex or int
            try:
                if val_str.lower().startswith("0x"):
                    parsed_params[var_name] = int(val_str, 16)
                else:
                    parsed_params[var_name] = int(val_str)
            except ValueError:
                parsed_params[var_name] = val_str

    return parsed_params


def export_pem_private_key(n: int, e: int, d: int, p: int, q: int) -> str:
    """Generate and return a PEM-formatted RSA private key string."""
    try:
        key = RSA.construct((n, e, d, p, q))
        return key.export_key().decode("utf-8")
    except Exception:
        # Construct with minimum (n, e, d)
        try:
            key = RSA.construct((n, e, d))
            return key.export_key().decode("utf-8")
        except Exception:
            return ""


class RSARunner:
    """Unified runner coordinating all RSA attacks with per-attack timeouts."""

    def __init__(self, offline: bool = False, attack_timeout: float = 3.0) -> None:
        self.offline = offline
        self.attack_timeout = attack_timeout
        self.attacks = [
            DirectRSADecrypt(),
            SmallEAttack(),
            WienerAttack(),
            FermatAttack(),
            PollardP1Attack(),
            PollardRhoAttack(),
            TrialDivisionAttack(),
            FactorDBAttack(),
            CommonModulusAttack(),
            HastadAttack(),
            SharedPrimeAttack(),
            PartialPAttack(),
            MultiPrimeAttack(),
            RabinAttack(),
        ]

    def run_all(
        self,
        n: int | None = None,
        e: int = 65537,
        c: int | None = None,
        flag_patterns: Sequence[str] | None = None,
        **extra_ctx: Any,
    ) -> tuple[list[Candidate], dict[str, str], str | None]:
        """Execute all applicable RSA attacks and return ranked Candidates, status logs, and recovered PEM."""
        ctx = {"n": n, "e": e, "c": c, "offline": self.offline, **extra_ctx}
        logs: dict[str, str] = {}
        all_candidates: list[Candidate] = []
        recovered_pem: str | None = None

        recovered_p: int | None = extra_ctx.get("p")
        recovered_q: int | None = extra_ctx.get("q")
        recovered_d: int | None = extra_ctx.get("d")

        for attack in self.attacks:
            if not attack.applicable(**ctx):
                logs[attack.name] = "SKIPPED"
                continue

            logs[attack.name] = "TRIED"
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(attack.run, **ctx)
                    results = future.result(timeout=self.attack_timeout)

                if results:
                    logs[attack.name] = "SUCCESS"
                    all_candidates.extend(results)

                    # Extract recovered parameters
                    for cand in results:
                        if "p" in cand.params and "q" in cand.params:
                            recovered_p = cand.params["p"]
                            recovered_q = cand.params["q"]
                        if "d" in cand.params:
                            recovered_d = cand.params["d"]
                else:
                    logs[attack.name] = "FAILED"
            except concurrent.futures.TimeoutError:
                logs[attack.name] = "TIMEOUT"
            except Exception:
                logs[attack.name] = "FAILED"

        # Attempt to export PEM if factors or private exponent found
        if n is not None and e is not None and recovered_d is not None:
            if recovered_p is not None and recovered_q is not None:
                recovered_pem = export_pem_private_key(n, e, recovered_d, recovered_p, recovered_q)
            else:
                try:
                    key = RSA.construct((n, e, recovered_d))
                    recovered_pem = key.export_key().decode("utf-8")
                except Exception:
                    pass

        ranked_candidates = rank(all_candidates, top=10, custom_flag_patterns=flag_patterns)
        return ranked_candidates, logs, recovered_pem
