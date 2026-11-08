"""End-to-end evaluation runner against all challenge categories."""

import json
from pathlib import Path
import sys
import time

from rich.console import Console
from rich.table import Table

from cryptokit.auto import AutoSolver
from cryptokit.classical import CaesarAttack, VigenereAttack
from cryptokit.encodings import peel
from cryptokit.hashes import crack_hash, identify_hash
from cryptokit.rsa.attacks.hastad import HastadAttack
from cryptokit.rsa.runner import RSARunner, parse_rsa_params
from cryptokit.xor import RepeatingKeyXORAttack

console = Console()
CHALLENGES_DIR = Path("E:/cryptokit/examples/challenges")


def main():
    table = Table(title="cryptokit End-to-End Challenge Evaluation Suite", show_lines=True)
    table.add_column("Challenge", style="cyan", width=24)
    table.add_column("Category", style="magenta", width=18)
    table.add_column("Status", width=10)
    table.add_column("Recovered Flag / Output", style="green")
    table.add_column("Time", style="dim", width=8)

    passed_count = 0
    total_count = 8

    # 1. Encoding Onion
    t0 = time.time()
    raw1 = (CHALLENGES_DIR / "01_encoding_onion.txt").read_bytes()
    cands1 = peel(raw1)
    flag1_recovered = cands1[0].text if cands1 and "flag{" in cands1[0].text else "FAILED"
    ok1 = "flag{encoding_onion_peeled_cleanly}" in flag1_recovered
    passed_count += 1 if ok1 else 0
    table.add_row("01_encoding_onion", "Encoding Peeling", "[green]PASS[/green]" if ok1 else "[red]FAIL[/red]", flag1_recovered, f"{time.time()-t0:.2f}s")

    # 2. Caesar Shift
    t0 = time.time()
    raw2 = (CHALLENGES_DIR / "02_caesar.txt").read_text(encoding="utf-8")
    caesar = CaesarAttack()
    cands2 = caesar.run(raw2)
    flag2_recovered = cands2[0].text if cands2 and "flag{" in cands2[0].text else "FAILED"
    ok2 = "flag{caesar_cipher_shift_17_discovered}" in flag2_recovered
    passed_count += 1 if ok2 else 0
    table.add_row("02_caesar", "Caesar Cipher", "[green]PASS[/green]" if ok2 else "[red]FAIL[/red]", flag2_recovered, f"{time.time()-t0:.2f}s")

    # 3. Vigenere
    t0 = time.time()
    raw3 = (CHALLENGES_DIR / "03_vigenere.txt").read_text(encoding="utf-8")
    vig = VigenereAttack()
    cands3 = vig.run(raw3, crib="flag{")
    flag3_recovered = cands3[0].text if cands3 and "flag{" in cands3[0].text else "FAILED"
    ok3 = "flag{vigenere_kasiski_and_ioc_solved}" in flag3_recovered
    passed_count += 1 if ok3 else 0
    table.add_row("03_vigenere", "Vigenère Cipher", "[green]PASS[/green]" if ok3 else "[red]FAIL[/red]", flag3_recovered[:60] + "...", f"{time.time()-t0:.2f}s")

    # 4. Repeating XOR
    t0 = time.time()
    hex4 = (CHALLENGES_DIR / "04_repeating_xor.hex").read_text(encoding="utf-8").strip()
    raw4 = bytes.fromhex(hex4)
    rxor = RepeatingKeyXORAttack()
    cands4 = rxor.run(raw4, min_size=2, max_size=8)
    flag4_recovered = cands4[0].text if cands4 and "flag{" in cands4[0].text else "FAILED"
    ok4 = "flag{repeating_xor_hamming_frequency_broken}" in flag4_recovered
    passed_count += 1 if ok4 else 0
    table.add_row("04_repeating_xor", "Repeating XOR", "[green]PASS[/green]" if ok4 else "[red]FAIL[/red]", flag4_recovered[:60] + "...", f"{time.time()-t0:.2f}s")

    # 5. RSA Fermat
    t0 = time.time()
    raw5 = (CHALLENGES_DIR / "05_rsa_fermat.txt").read_text(encoding="utf-8")
    p5 = parse_rsa_params(raw5)
    rsa_runner = RSARunner(offline=True, attack_timeout=5.0)
    cands5, _, _ = rsa_runner.run_all(**p5)
    flag5_recovered = cands5[0].text if cands5 and "flag{" in cands5[0].text else "FAILED"
    ok5 = "flag{fermat_close_primes_factored}" in flag5_recovered
    passed_count += 1 if ok5 else 0
    table.add_row("05_rsa_fermat", "RSA Fermat", "[green]PASS[/green]" if ok5 else "[red]FAIL[/red]", flag5_recovered, f"{time.time()-t0:.2f}s")

    # 6. RSA Wiener
    t0 = time.time()
    raw6 = (CHALLENGES_DIR / "06_rsa_wiener.txt").read_text(encoding="utf-8")
    p6 = parse_rsa_params(raw6)
    cands6, _, _ = rsa_runner.run_all(**p6)
    flag6_recovered = cands6[0].text if cands6 and "flag{" in cands6[0].text else "FAILED"
    ok6 = "flag{wiener_small_d_fractions_attack}" in flag6_recovered
    passed_count += 1 if ok6 else 0
    table.add_row("06_rsa_wiener", "RSA Wiener", "[green]PASS[/green]" if ok6 else "[red]FAIL[/red]", flag6_recovered, f"{time.time()-t0:.2f}s")

    # 7. RSA Hastad
    t0 = time.time()
    raw7 = json.loads((CHALLENGES_DIR / "07_rsa_hastad.json").read_text(encoding="utf-8"))
    hastad = HastadAttack()
    cands7 = hastad.run(e=raw7["e"], moduli=raw7["moduli"], ciphertexts=raw7["ciphertexts"])
    flag7_recovered = cands7[0].text if cands7 and "flag{" in cands7[0].text else "FAILED"
    ok7 = "flag{hastad_crt_broadcast_3_keys}" in flag7_recovered
    passed_count += 1 if ok7 else 0
    table.add_row("07_rsa_hastad", "RSA Hastad", "[green]PASS[/green]" if ok7 else "[red]FAIL[/red]", flag7_recovered, f"{time.time()-t0:.2f}s")

    # 8. Hash Cracking with Rules
    t0 = time.time()
    raw8_h = (CHALLENGES_DIR / "08_hash.txt").read_text(encoding="utf-8").strip()
    words8 = (CHALLENGES_DIR / "08_wordlist.txt").read_text(encoding="utf-8").splitlines()
    cracked = crack_hash(raw8_h, words8, use_rules=True)
    res8 = f"{cracked[0]} ({cracked[1]})" if cracked else "FAILED"
    ok8 = cracked is not None and cracked[0] == "supersecret123"
    passed_count += 1 if ok8 else 0
    table.add_row("08_hash_rules", "Hash Dictionary", "[green]PASS[/green]" if ok8 else "[red]FAIL[/red]", res8, f"{time.time()-t0:.2f}s")

    console.print(table)
    console.print(f"\n[bold]Summary:[/bold] [green]{passed_count}/{total_count}[/green] challenges successfully solved.")

    if passed_count != total_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
