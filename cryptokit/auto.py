"""Automated CTF challenge solver engine: recursive peeling, multi-cipher dispatch, RSA detection, and ECB flagging."""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any, Sequence

from cryptokit.base import Candidate
from cryptokit.classical import (
    AffineAttack,
    AtbashAttack,
    CaesarAttack,
    MonoalphabeticSubstitutionAttack,
    RailFenceAttack,
    VigenereAttack,
)
from cryptokit.encodings import peel
from cryptokit.rsa.runner import RSARunner, parse_rsa_params
from cryptokit.scoring import rank, score
from cryptokit.symmetric import detect_ecb
from cryptokit.xor import RepeatingKeyXORAttack, SingleByteXORAttack


class AutoSolver:
    """Unified solver executing multi-layer peeling, classical/XOR cryptanalysis, and RSA dispatch."""

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout
        self.single_xor = SingleByteXORAttack()
        self.rep_xor = RepeatingKeyXORAttack()
        self.caesar = CaesarAttack()
        self.atbash = AtbashAttack()
        self.affine = AffineAttack()
        self.rail_fence = RailFenceAttack()
        self.vigenere = VigenereAttack()
        self.substitution = MonoalphabeticSubstitutionAttack()

    def is_rsa_input(self, text: str) -> bool:
        """Check if input text appears to be RSA parameters or keys."""
        t = text.strip()
        if "-----BEGIN" in t:
            return True
        if "n =" in t or "n=" in t or "n :" in t or "n:" in t:
            if "e =" in t or "e=" in t or "c =" in t or "c=" in t:
                return True
        if t.startswith("{") and '"n"' in t:
            return True
        return False

    def solve_layer(
        self,
        data: bytes,
        layer_method: str = "",
        crib: str | None = None,
        flag_patterns: Sequence[str] | None = None,
    ) -> list[Candidate]:
        """Run all classical and XOR attacks against a single peeled layer of data."""
        candidates: list[Candidate] = []

        # 1. Single-byte XOR
        try:
            for c in self.single_xor.run(data=data, top=3, flag_patterns=flag_patterns):
                method_name = f"{layer_method} -> {c.method}" if layer_method else c.method
                candidates.append(Candidate(plaintext=c.plaintext, method=method_name, params=c.params, score=c.score))
        except Exception:
            pass

        # 2. Repeating-key XOR
        if len(data) >= 16:
            try:
                for c in self.rep_xor.run(data=data, top=3, flag_patterns=flag_patterns):
                    method_name = f"{layer_method} -> {c.method}" if layer_method else c.method
                    candidates.append(Candidate(plaintext=c.plaintext, method=method_name, params=c.params, score=c.score))
            except Exception:
                pass

        # Text-based solvers if data looks like text
        text = data.decode("utf-8", errors="replace")
        printable_cnt = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        is_textish = printable_cnt / max(1, len(data)) > 0.7

        if is_textish:
            # 3. Caesar
            try:
                for c in self.caesar.run(data=data, top=3, flag_patterns=flag_patterns):
                    method_name = f"{layer_method} -> {c.method}" if layer_method else c.method
                    candidates.append(Candidate(plaintext=c.plaintext, method=method_name, params=c.params, score=c.score))
            except Exception:
                pass

            # 4. Atbash
            try:
                for c in self.atbash.run(data=data, flag_patterns=flag_patterns):
                    method_name = f"{layer_method} -> {c.method}" if layer_method else c.method
                    candidates.append(Candidate(plaintext=c.plaintext, method=method_name, params=c.params, score=c.score))
            except Exception:
                pass

            # 5. Affine
            try:
                for c in self.affine.run(data=data, top=2, flag_patterns=flag_patterns):
                    method_name = f"{layer_method} -> {c.method}" if layer_method else c.method
                    candidates.append(Candidate(plaintext=c.plaintext, method=method_name, params=c.params, score=c.score))
            except Exception:
                pass

            # 6. Rail Fence
            if len(data) >= 6:
                try:
                    for c in self.rail_fence.run(data=data, top=2, flag_patterns=flag_patterns):
                        method_name = f"{layer_method} -> {c.method}" if layer_method else c.method
                        candidates.append(Candidate(plaintext=c.plaintext, method=method_name, params=c.params, score=c.score))
                except Exception:
                    pass

            # 7. Vigenere
            try:
                for c in self.vigenere.run(data=data, crib=crib, top=3, flag_patterns=flag_patterns):
                    method_name = f"{layer_method} -> {c.method}" if layer_method else c.method
                    candidates.append(Candidate(plaintext=c.plaintext, method=method_name, params=c.params, score=c.score))
            except Exception:
                pass

            # 8. Substitution (simulated annealing)
            if len(data) >= 35:
                try:
                    for c in self.substitution.run(data=data, iterations=600, restarts=2, flag_patterns=flag_patterns):
                        method_name = f"{layer_method} -> {c.method}" if layer_method else c.method
                        candidates.append(Candidate(plaintext=c.plaintext, method=method_name, params=c.params, score=c.score))
                except Exception:
                    pass

        return candidates

    def solve(
        self,
        raw_input: bytes | str,
        crib: str | None = None,
        flag_patterns: Sequence[str] | None = None,
        find_all: bool = False,
        top: int = 5,
    ) -> tuple[list[Candidate], dict[str, Any]]:
        """Orchestrate automated solving across encodings, ciphers, and RSA."""
        start_time = time.time()
        diagnostics: dict[str, Any] = {"rsa": False, "ecb_flag": False, "layers_explored": 0}

        text_repr = raw_input.decode("utf-8", errors="replace") if isinstance(raw_input, bytes) else raw_input
        data_bytes = raw_input.encode("utf-8") if isinstance(raw_input, str) else raw_input

        # 1. RSA detection check
        if self.is_rsa_input(text_repr):
            diagnostics["rsa"] = True
            params = parse_rsa_params(text_repr)
            runner = RSARunner(offline=False, attack_timeout=3.0)
            rsa_cands, logs, pem = runner.run_all(**params, flag_patterns=flag_patterns)
            diagnostics["rsa_logs"] = logs
            diagnostics["pem"] = pem
            if rsa_cands:
                return rsa_cands[:top], diagnostics

        # 2. Check for possible ECB mode
        ecb_check = detect_ecb(data_bytes)
        if ecb_check["is_ecb"]:
            diagnostics["ecb_flag"] = True
            diagnostics["ecb_details"] = ecb_check

        # 3. Recursive peeling of encodings
        from cryptokit.encodings import peel_layers

        peeled_layers = peel_layers(data_bytes, max_depth=6)
        diagnostics["layers_explored"] = len(peeled_layers)

        all_candidates: list[Candidate] = []
        for l_bytes, chain in peeled_layers:
            m_str = " -> ".join(chain) if chain else "raw_input"
            l_score = score(l_bytes, custom_flag_patterns=flag_patterns)
            all_candidates.append(Candidate(plaintext=l_bytes, method=m_str, params={"chain": chain}, score=l_score))

        # Check if an immediate peel recovered a flag
        if not find_all and any(c.score > 1000.0 for c in all_candidates):
            return rank(all_candidates, top=top, custom_flag_patterns=flag_patterns), diagnostics

        # 4. Run classical/XOR solvers at each unpeeled layer
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for l_bytes, chain in peeled_layers:
                chain_name = " -> ".join(chain) if chain else ""
                futures.append(
                    executor.submit(
                        self.solve_layer,
                        l_bytes,
                        chain_name,
                        crib,
                        flag_patterns,
                    )
                )

            for fut in concurrent.futures.as_completed(futures):
                try:
                    cands = fut.result()
                    all_candidates.extend(cands)
                    if not find_all and any(c.score > 1000.0 for c in cands):
                        break
                except Exception:
                    continue

        diagnostics["elapsed_seconds"] = round(time.time() - start_time, 2)
        ranked = rank(all_candidates, top=top, custom_flag_patterns=flag_patterns)
        return ranked, diagnostics
