"""Typer-based command-line interface for cryptokit with Rich table formatting."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Annotated, Any, Optional
from getpass import getpass

if sys.platform == "win32":
    if sys.stdout is not None and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stderr is not None and hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cryptokit.auto import AutoSolver
from cryptokit.base import Candidate
from cryptokit.classical import (
    AffineAttack,
    AtbashAttack,
    CaesarAttack,
    MonoalphabeticSubstitutionAttack,
    RailFenceAttack,
    VigenereAttack,
)
from cryptokit.encodings import Decoder, peel
from cryptokit.hashes import crack_hash, hash_length_extension, identify_hash
from cryptokit.rsa.runner import RSARunner, parse_rsa_params
from cryptokit.scoring import rank, score
from cryptokit.symmetric import aes_brute_force, cbc_bit_flip, detect_ecb
from cryptokit.utils import hexdump

app = typer.Typer(
    name="cryptokit",
    help="Fast, modular toolkit for solving CTF cryptography challenges.",
    no_args_is_help=True,
)
rsa_app = typer.Typer(name="rsa", help="RSA cryptanalysis attacks and solvers.", no_args_is_help=True)
aes_app = typer.Typer(name="aes", help="Symmetric / AES attacks and utilities.", no_args_is_help=True)
hash_app = typer.Typer(name="hash", help="Hash identification, cracking, and length extension.", no_args_is_help=True)

app.add_typer(rsa_app, name="rsa")
app.add_typer(aes_app, name="aes")
app.add_typer(hash_app, name="hash")

console = Console()


def resolve_input(
    data: str | None = None,
    file: Path | None = None,
    use_stdin: bool = False,
    is_hex: bool = False,
    is_b64: bool = False,
) -> bytes:
    """Resolve input bytes from argument, file, or standard input."""
    raw: bytes
    if file is not None:
        if not file.exists():
            console.print(f"[bold red]Error:[/bold red] File not found: [yellow]{file}[/yellow]")
            raise typer.Exit(code=1)
        try:
            raw = file.read_bytes()
        except Exception as err:
            console.print(f"[bold red]Error reading file {file}:[/bold red] {err}")
            raise typer.Exit(code=1)
    elif use_stdin or not sys.stdin.isatty() and data is None:
        raw = sys.stdin.buffer.read()
    elif data is not None:
        raw = data.encode("utf-8")
    else:
        console.print("[bold red]Error:[/bold red] No input provided via argument, --file, or stdin.")
        raise typer.Exit(code=1)

    if is_hex:
        clean = raw.decode("utf-8", errors="replace").strip().replace(" ", "").replace("\n", "").replace("\r", "")
        if clean.lower().startswith("0x"):
            clean = clean[2:]
        try:
            return bytes.fromhex(clean)
        except ValueError as err:
            console.print(f"[bold red]Error:[/bold red] Invalid hexadecimal input: {err}")
            raise typer.Exit(code=1)
    if is_b64:
        try:
            clean = raw.strip()
            return base64.b64decode(clean)
        except Exception as err:
            console.print(f"[bold red]Error:[/bold red] Invalid base64 input: {err}")
            raise typer.Exit(code=1)

    return raw


def display_results(
    candidates: list[Candidate],
    as_json: bool = False,
    top: int = 5,
    title: str = "Results",
    diagnostics: dict[str, Any] | None = None,
) -> None:
    """Render candidates as a Rich table or output JSON."""
    if as_json:
        out = [
            {
                "score": c.score,
                "method": c.method,
                "text": c.text,
                "hex": c.plaintext.hex(),
                "params": {k: (str(v) if isinstance(v, (int, bytes)) and len(str(v)) > 50 else v) for k, v in c.params.items()},
            }
            for c in candidates[:top]
        ]
        res_dict: dict[str, Any] = {"candidates": out}
        if diagnostics:
            res_dict["diagnostics"] = diagnostics
        console.print_json(data=res_dict)
        return

    if diagnostics:
        diag_lines = [f"[bold]{k}:[/bold] {v}" for k, v in diagnostics.items() if k not in ("rsa_logs", "pem")]
        if diag_lines:
            console.print(Panel(" | ".join(diag_lines), title="Diagnostics", border_style="cyan"))

    if not candidates:
        console.print(Panel("[yellow]No candidates found.[/yellow]", title=title, border_style="yellow"))
        return

    table = Table(title=title, show_lines=True)
    table.add_column("Rank", style="dim", width=5)
    table.add_column("Score", style="bold green", width=9)
    table.add_column("Method", style="cyan", width=22)
    table.add_column("Plaintext Preview", style="bright_white")
    table.add_column("Parameters", style="dim magenta")

    for i, c in enumerate(candidates[:top], 1):
        preview = c.text.replace("\ufffd", "?")
        # Sanitize unprintable characters for safe terminal output across all console codepages
        preview = "".join(ch if (ch.isprintable() or ch == " ") else f"\\x{ord(ch):02x}" for ch in preview)
        # Truncate very long outputs
        if len(preview) > 120:
            preview = preview[:117] + "..."
        # Highlight flag pattern if present
        if "flag{" in preview.lower() or "ctf{" in preview.lower():
            preview = f"[bold yellow]{preview}[/bold yellow]"

        param_str = ", ".join(f"{k}={v}" for k, v in c.params.items() if not str(v).startswith("0x") and len(str(v)) < 30)
        table.add_row(str(i), f"{c.score:.1f}", c.method, preview, param_str)

    console.print(table)


# --- cryptokit auto ---

@app.command("auto")
def cmd_auto(
    data: Annotated[Optional[str], typer.Argument(help="Ciphertext string or pasted params")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Read input from file")] = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read from stdin pipe")] = False,
    is_hex: Annotated[bool, typer.Option("--hex", help="Decode input as hex bytes")] = False,
    is_b64: Annotated[bool, typer.Option("--b64", help="Decode input as base64 bytes")] = False,
    crib: Annotated[Optional[str], typer.Option("--crib", help="Known crib substring (e.g. 'flag{')")] = None,
    flag_format: Annotated[Optional[str], typer.Option("--flag-format", help="Custom regex pattern for flags")] = None,
    all_results: Annotated[bool, typer.Option("--all", help="Explore all branches without early exit")] = False,
    top: Annotated[int, typer.Option("--top", "-n", help="Number of candidates to output")] = 5,
    timeout: Annotated[float, typer.Option("--timeout", help="Timeout in seconds")] = 15.0,
    as_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
) -> None:
    """Run full automated peeling, cipher attacks, and RSA solving."""
    raw = resolve_input(data, file, stdin, is_hex, is_b64)
    flag_patterns = [flag_format] if flag_format else None

    solver = AutoSolver(timeout=timeout)
    candidates, diag = solver.solve(raw, crib=crib, flag_patterns=flag_patterns, find_all=all_results, top=top)
    display_results(candidates, as_json=as_json, top=top, title="cryptokit auto results", diagnostics=diag)


# --- cryptokit decode ---

@app.command("decode")
def cmd_decode(
    data: Annotated[Optional[str], typer.Argument(help="Data to decode or peel")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Read input from file")] = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read from stdin pipe")] = False,
    max_depth: Annotated[int, typer.Option("--max-depth", "-d", help="Max peeling depth")] = 8,
    top: Annotated[int, typer.Option("--top", "-n", help="Number of candidates")] = 5,
    as_json: Annotated[bool, typer.Option("--json", help="Output as JSON")] = False,
) -> None:
    """Recursively peel encodings (base64, hex, zlib, morse, etc.)."""
    raw = resolve_input(data, file, stdin)
    candidates = peel(raw, max_depth=max_depth)
    display_results(candidates, as_json=as_json, top=top, title="cryptokit decode (peel)")


# --- Classical Cipher Commands ---

@app.command("caesar")
def cmd_caesar(
    data: Annotated[Optional[str], typer.Argument(help="Ciphertext to brute force")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f")] = None,
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    top: Annotated[int, typer.Option("--top", "-n")] = 5,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Brute force Caesar / ROT shifts (1..25)."""
    raw = resolve_input(data, file, stdin)
    attack = CaesarAttack()
    candidates = attack.run(raw, top=top)
    display_results(candidates, as_json=as_json, top=top, title="Caesar Brute Force")


@app.command("vigenere")
def cmd_vigenere(
    data: Annotated[Optional[str], typer.Argument(help="Ciphertext")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f")] = None,
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    key: Annotated[Optional[str], typer.Option("--key", "-k", help="Vigenere key if known")] = None,
    crib: Annotated[Optional[str], typer.Option("--crib", "-c", help="Known crib substring")] = None,
    top: Annotated[int, typer.Option("--top", "-n")] = 5,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Analyze and solve Vigenère cipher using frequency analysis or cribs."""
    raw = resolve_input(data, file, stdin)
    attack = VigenereAttack()
    candidates = attack.run(raw, key=key, crib=crib, top=top)
    display_results(candidates, as_json=as_json, top=top, title="Vigenere Solve")


@app.command("xor")
def cmd_xor(
    data: Annotated[Optional[str], typer.Argument(help="Ciphertext")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f")] = None,
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    is_hex: Annotated[bool, typer.Option("--hex")] = False,
    is_b64: Annotated[bool, typer.Option("--b64")] = False,
    crib: Annotated[Optional[str], typer.Option("--crib", "-c", help="Known crib")] = None,
    repeating: Annotated[bool, typer.Option("--repeating", "-r", help="Run repeating-key XOR")] = False,
    top: Annotated[int, typer.Option("--top", "-n")] = 5,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Solve single-byte or repeating-key XOR ciphers."""
    from cryptokit.xor import KnownPlaintextXORAttack, RepeatingKeyXORAttack, SingleByteXORAttack

    raw = resolve_input(data, file, stdin, is_hex, is_b64)
    if crib:
        kp_attack = KnownPlaintextXORAttack()
        candidates = kp_attack.run(raw, crib=crib, top=top)
    elif repeating:
        rep_attack = RepeatingKeyXORAttack()
        candidates = rep_attack.run(raw, top=top)
    else:
        sb_attack = SingleByteXORAttack()
        candidates = sb_attack.run(raw, top=top)

    display_results(candidates, as_json=as_json, top=top, title="XOR Solver")


@app.command("substitution")
def cmd_substitution(
    data: Annotated[Optional[str], typer.Argument(help="Ciphertext")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f")] = None,
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    iterations: Annotated[int, typer.Option("--iterations", "-i")] = 1500,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Break monoalphabetic substitution cipher with simulated annealing."""
    raw = resolve_input(data, file, stdin)
    attack = MonoalphabeticSubstitutionAttack()
    candidates = attack.run(raw, iterations=iterations)
    display_results(candidates, as_json=as_json, top=3, title="Substitution Annealing")


@app.command("railfence")
def cmd_railfence(
    data: Annotated[Optional[str], typer.Argument(help="Ciphertext")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f")] = None,
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    top: Annotated[int, typer.Option("--top", "-n")] = 5,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Brute force Rail Fence transposition cipher."""
    raw = resolve_input(data, file, stdin)
    attack = RailFenceAttack()
    candidates = attack.run(raw, top=top)
    display_results(candidates, as_json=as_json, top=top, title="Rail Fence Solver")


# --- RSA Subcommands ---

@rsa_app.command("inspect-pem")
def cmd_rsa_inspect_pem(
    pem_file: Annotated[Path, typer.Argument(help="Path to RSA PEM file")],
) -> None:
    """Inspect an RSA PEM file, including encrypted private keys."""

    if not pem_file.is_file():
        console.print(f"[bold red]Error:[/bold red] File not found: {pem_file}")
        raise typer.Exit(code=1)

    try:
        content = pem_file.read_text(encoding="utf-8")
        password = getpass("Enter PEM passphrase (press Enter if unencrypted): ")

        from cryptokit.rsa.runner import parse_rsa_params

        params = parse_rsa_params(
            content,
            passphrase=password or None,
        )

        table = Table(title="RSA PEM Inspection")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Modulus (n)", str(params["n"]))
        table.add_row("Public exponent (e)", str(params["e"]))
        table.add_row(
            "Private key",
            "Available" if "d" in params else "Not available",
        )

        console.print(table)
        console.print("[bold green]PEM imported successfully.[/bold green]")

    except (ValueError, KeyError, OSError) as err:
        console.print(f"[bold red]PEM inspection failed:[/bold red] {err}")
        raise typer.Exit(code=1)

@rsa_app.command("calculate")
def cmd_rsa_calculate(
    p: Annotated[int, typer.Option("--p", help="First RSA prime number")],
    q: Annotated[int, typer.Option("--q", help="Second RSA prime number")],
) -> None:
    """Calculate the RSA modulus n from two prime numbers."""
    from sympy import isprime

    if p <= 1 or q <= 1:
        console.print("[bold red]Error:[/bold red] p and q must be greater than 1.")
        raise typer.Exit(code=1)

    if not isprime(p):
        console.print(f"[bold red]Error:[/bold red] p={p} is not a prime number.")
        raise typer.Exit(code=1)

    if not isprime(q):
        console.print(f"[bold red]Error:[/bold red] q={q} is not a prime number.")
        raise typer.Exit(code=1)

    if p == q:
        console.print("[bold red]Error:[/bold red] p and q must be distinct primes.")
        raise typer.Exit(code=1)

    n = p * q

    table = Table(title="RSA Modulus Calculation")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("p", str(p))
    table.add_row("q", str(q))
    table.add_row("n = p × q", str(n))

    console.print(table)

@rsa_app.command("auto")
def cmd_rsa_auto(
    params_file: Annotated[Optional[Path], typer.Option("--params", "-p", help="Path to params file (PEM/JSON/text)")] = None,
    n_arg: Annotated[Optional[str], typer.Option("--n", help="Modulus n (dec or hex)")] = None,
    e_arg: Annotated[Optional[str], typer.Option("--e", help="Public exponent e (dec or hex)")] = None,
    c_arg: Annotated[Optional[str], typer.Option("--c", help="Ciphertext c (dec or hex)")] = None,
    offline: Annotated[bool, typer.Option("--offline", help="Disable online Factordb queries")] = False,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run all RSA factorization and decryption attacks automatically."""
    ctx: dict[str, Any] = {}
    if params_file is not None:
        if not params_file.exists():
            console.print(f"[bold red]Error:[/bold red] Params file not found: [yellow]{params_file}[/yellow]")
            raise typer.Exit(code=1)
        try:
            content = params_file.read_text(encoding="utf-8")
            ctx = parse_rsa_params(content)
        except Exception as err:
            console.print(f"[bold red]Error parsing params file:[/bold red] {err}")
            raise typer.Exit(code=1)

    try:
        if n_arg is not None:
            ctx["n"] = int(n_arg, 16) if n_arg.lower().startswith("0x") else int(n_arg)
        if e_arg is not None:
            ctx["e"] = int(e_arg, 16) if e_arg.lower().startswith("0x") else int(e_arg)
        elif "e" not in ctx:
            ctx["e"] = 65537

        if c_arg is not None:
            ctx["c"] = int(c_arg, 16) if c_arg.lower().startswith("0x") else int(c_arg)
    except ValueError as err:
        console.print(f"[bold red]Error:[/bold red] Invalid number format for RSA argument: {err}")
        raise typer.Exit(code=1)

    runner = RSARunner(offline=offline, attack_timeout=5.0)
    candidates, logs, pem = runner.run_all(**ctx)

    display_results(candidates, as_json=as_json, title="RSA Attacks", diagnostics={"attacks_tried": len(logs)})
    if pem and not as_json:
        console.print(Panel(pem, title="Recovered RSA Private Key (PEM)", border_style="green"))


# --- AES Subcommands ---

@aes_app.command("ecb-detect")
def cmd_ecb_detect(
    data: Annotated[Optional[str], typer.Argument(help="Ciphertext")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f")] = None,
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    is_hex: Annotated[bool, typer.Option("--hex")] = True,
) -> None:
    """Detect ECB mode repetition in ciphertext blocks."""
    raw = resolve_input(data, file, stdin, is_hex=is_hex)
    res = detect_ecb(raw)
    status_color = "red" if res["is_ecb"] else "green"
    console.print(Panel(
        f"ECB Detected: [{status_color}]{res['is_ecb']}[/{status_color}]\n"
        f"Confidence: {res['confidence']:.2f}\n"
        f"Duplicate blocks: {res['duplicate_blocks']} / {res['total_blocks']}",
        title="ECB Repetition Analysis",
    ))


@aes_app.command("cbc-flip")
def cmd_cbc_flip(
    ciphertext_hex: Annotated[str, typer.Option("--ct", help="Original ciphertext in hex")],
    original: Annotated[str, typer.Option("--orig", help="Original plaintext snippet to alter")],
    desired: Annotated[str, typer.Option("--desired", help="Desired altered plaintext snippet")],
    offset: Annotated[int, typer.Option("--offset", help="Offset of plaintext snippet (>= 16)")],
) -> None:
    """Generate altered ciphertext via CBC bit-flipping attack."""
    try:
        clean_ct = ciphertext_hex.strip().replace(" ", "")
        ct = bytes.fromhex(clean_ct)
    except ValueError as err:
        console.print(f"[bold red]Error:[/bold red] Invalid hex ciphertext: {err}")
        raise typer.Exit(code=1)
    try:
        flipped = cbc_bit_flip(ct, original.encode(), desired.encode(), offset=offset)
        console.print(Panel(f"Flipped Ciphertext (hex):\n[bold green]{flipped.hex()}[/bold green]", title="CBC Bit Flip"))
    except Exception as err:
        console.print(f"[bold red]Error performing CBC flip:[/bold red] {err}")
        raise typer.Exit(code=1)


# --- Hash Subcommands ---

@hash_app.command("identify")
def cmd_hash_identify(hash_str: Annotated[str, typer.Argument(help="Hash string to inspect")]) -> None:
    """Identify hash algorithm by format and length."""
    matches = identify_hash(hash_str)
    console.print(Panel(f"Identified types: [bold cyan]{', '.join(matches)}[/bold cyan]", title="Hash Identification"))


@hash_app.command("crack")
def cmd_hash_crack(
    target_hash: Annotated[str, typer.Argument(help="Target hash to crack")],
    wordlist_file: Annotated[Path, typer.Option("--wordlist", "-w", help="Path to dictionary file")],
    algo: Annotated[Optional[str], typer.Option("--algo", "-a", help="Algorithm (md5, sha1, sha256...)")] = None,
    rules: Annotated[bool, typer.Option("--rules/--no-rules", help="Apply mutation rules")] = True,
) -> None:
    """Crack hash with wordlist and optional transformation rules."""
    if not wordlist_file.exists():
        console.print(f"[bold red]Error:[/bold red] Wordlist file not found: [yellow]{wordlist_file}[/yellow]")
        raise typer.Exit(code=1)
    try:
        words = wordlist_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as err:
        console.print(f"[bold red]Error reading wordlist:[/bold red] {err}")
        raise typer.Exit(code=1)
    res = crack_hash(target_hash, words, algorithm=algo, use_rules=rules)
    if res:
        plaintext, detected_algo = res
        console.print(Panel(f"CRACKED!\nPlaintext: [bold green]{plaintext}[/bold green]\nAlgorithm: {detected_algo}", title="Hash Result"))
    else:
        console.print("[red]Hash not found in wordlist.[/red]")


@hash_app.command("extend")
def cmd_hash_extend(
    algo: Annotated[str, typer.Option("--algo", "-a", help="Hash algorithm: md5, sha1, or sha256")],
    hash_str: Annotated[str, typer.Option("--hash", "-h", help="Original hash")],
    original_msg: Annotated[str, typer.Option("--msg", "-m", help="Original message")],
    key_len: Annotated[int, typer.Option("--key-len", "-k", help="Secret key length")],
    append_str: Annotated[str, typer.Option("--append", help="Data to append")],
) -> None:
    """Perform Merkle-Damgard hash length extension attack."""
    try:
        payload, new_hash = hash_length_extension(
            algo,
            hash_str,
            original_msg.encode("utf-8"),
            key_length=key_len,
            append_data=append_str.encode("utf-8"),
        )
    except ValueError as err:
        console.print(f"[bold red]Error:[/bold red] {err}")
        raise typer.Exit(code=1)
    except Exception as err:
        console.print(f"[bold red]Hash extension failed:[/bold red] {err}")
        raise typer.Exit(code=1)
    console.print(Panel(
        f"Forged Hash: [bold green]{new_hash}[/bold green]\n"
        f"Forged Payload (Hex): {payload.hex()}\n"
        f"Hexdump:\n{hexdump(payload)}",
        title="Hash Length Extension",
    ))


if __name__ == "__main__":
    app()
