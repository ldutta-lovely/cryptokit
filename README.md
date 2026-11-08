# cryptokit 🧰

A fast, modular, high-performance Python 3.11+ toolkit and CLI designed for solving Capture The Flag (CTF) cryptography challenges under time pressure.

```
       _____                      _          _     _ _
      / ____|                    | |        | |   (_) |
     | |     _ __ _   _ _ __  ___| |_ ___  _| |___ _| |_
     | |    | '__| | | | '_ \/ __| __/ _ \| |/ / | | __|
     | |____| |  | |_| | |_) \__ \ || (_) | |   <| | |_
      \_____|_|   \__, | .__/|___/\__\___/|_|_|\_\_|\__|
                   __/ | |
                  |___/|_|
```

---

## ⚡ Key Highlights

- **Unified Scoring & Auto Pipeline**: Run `cryptokit auto <input>` to automatically peel multi-layer encodings, dispatch classical and XOR solvers, detect repeated ECB blocks, and hand off to RSA factorization.
- **Candidate Ranking Engine**: Uniform `@dataclass Candidate` returned across all attacks with chi-squared English frequency analysis, printable ASCII ratios, Shannon entropy penalties, and automated CTF flag regex matching (`flag{...}`, `ctf{...}`, `HTB{...}`, etc.).
- **13+ Modular RSA Attacks**: Small $e$, Fermat close primes, Wiener continued fractions, Hastad broadcast, Pollard $p-1$ / $\rho$, Common Modulus, Shared prime batch GCD, multi-prime RSA, partial $p$ leakage, Rabin cryptosystem, and PEM private key export.
- **Symmetric Tools**: PKCS#7 pad/unpad validation, ECB block repetition detection, byte-at-a-time ECB suffix decryption, CBC bit-flipping, and CBC padding oracle attacks against custom oracles.
- **Hashes**: Format/length identifier, dictionary cracker with mutation rules (casing, leetspeak, suffixes), and from-scratch Merkle-Damgård hash length extension attacks for MD5, SHA-1, and SHA-256.

---

## 🚀 Installation

### Using pip / virtual environment (Python 3.11+)

```bash
git clone https://github.com/example/cryptokit.git
cd cryptokit
python -m venv .venv

# Linux / macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate

# Install in editable mode with dependencies
pip install -e .
```

### Dependencies
- `pycryptodome` (cryptographic primitives & ASN.1 PEM generation)
- `sympy` (prime verification & number theory)
- `typer` (CLI commands and subcommands)
- `rich` (beautiful colored terminal tables & panels)
- `requests` (Factordb API queries)
- `gmpy2` (optional accelerated integer root and arithmetic; pure-Python fallbacks included)

---

## 📖 CTF Cheat Sheet: Which Command to Use?

| Challenge Type / Symptoms | Recommended Command | Key Flags |
|---|---|---|
| **Unknown ciphertext / mystery blob** | `cryptokit auto <input>` | `--file`, `--crib "flag{"`, `--all` |
| **Layered encodings (b64/hex/zlib/etc.)** | `cryptokit decode <input>` | `--max-depth 10` |
| **Shifted alphabet text (ROT13, etc.)** | `cryptokit caesar <input>` | `--top 5` |
| **Polyalphabetic letter shifts** | `cryptokit vigenere <input>` | `--crib "flag{"`, `--key "KEY"` |
| **Single-byte or repeating-key XOR** | `cryptokit xor <input>` | `--hex`, `--b64`, `--repeating`, `--crib` |
| **Random monoalphabetic substitution** | `cryptokit substitution <input>` | `--iterations 2000` |
| **Zig-zag / rail transposition** | `cryptokit railfence <input>` | `--top 5` |
| **RSA parameters given ($n, e, c$)** | `cryptokit rsa auto` | `--params params.txt`, `--n`, `--e`, `--c`, `--offline` |
| **Repeated 16-byte blocks in AES** | `cryptokit aes ecb-detect <hex>` | `--hex` |
| **CBC plaintext injection (e.g. role=admin)**| `cryptokit aes cbc-flip` | `--ct <hex> --orig "role=user" --desired "role=admi" --offset 32` |
| **Unknown hash string** | `cryptokit hash identify <hash>` | |
| **Cracking password hash** | `cryptokit hash crack <hash>` | `-w wordlist.txt --rules` |
| **Forging HMAC-like hash without key** | `cryptokit hash extend` | `-a md5 -h <hash> -m <orig> -k <keylen> --append <data>` |

---

## 💻 CLI Usage Examples

### 1. Unified Automated Solver (`auto`)
```bash
# Automatically detects encodings and breaks underlying ciphers
cryptokit auto "666c61677b73616d706c655f666c61677d" --hex

# With custom CTF flag format
cryptokit auto "..." --flag-format "MyCTF\{.*?\}"

# Pipe from standard input
cat secret_challenge.txt | cryptokit auto --stdin
```

### 2. Multi-Layer Decoding (`decode`)
```bash
# Peels layers: base64 -> hex -> zlib -> text
cryptokit decode "eJxLy0lMr85JrEwtik+qjIcwylPjS/OS88uAzOLUsvw0ALj+D34="
```

### 3. Classical Ciphers
```bash
# Caesar / ROT brute force
cryptokit caesar "synt{ebg13_vf_rnfl}"

# Vigenère frequency analysis and crib recovery
cryptokit vigenere "Twe quicz brown uox..." --crib "flag{"

# Rail fence cipher
cryptokit railfence "f{azeocla_agrc_yrl_fnigzve}"

# Monoalphabetic substitution (simulated annealing with quadgrams)
cryptokit substitution "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj..."
```

### 4. XOR Attacks
```bash
# Single-byte XOR brute force
cryptokit xor --hex "1b171c1b460814131b461704460714131b"

# Repeating-key XOR using normalized Hamming distance
cryptokit xor --repeating --file ciphertext.bin

# Known-plaintext XOR key deduction
cryptokit xor --hex "..." --crib "flag{"
```

### 5. RSA Cryptanalysis Suite
```bash
# Paste parameters directly from challenge file (JSON or text)
cryptokit rsa auto --params challenge.txt

# Or pass parameters on the command line
cryptokit rsa auto --n 123456789... --e 3 --c 987654321...

# Run offline without querying FactorDB
cryptokit rsa auto --params rsa.json --offline
```

### 6. Symmetric Cryptography
```bash
# Check if ciphertext has repeating ECB blocks
cryptokit aes ecb-detect "8d8a7c2b3e..." --hex

# Compute CBC bit-flip delta
cryptokit aes cbc-flip --ct "a1b2..." --orig "role=user" --desired "role=admi" --offset 32
```

### 7. Hashes
```bash
# Identify hash algorithms
cryptokit hash identify "5d41402abc4b2a76b9719d911017c592"

# Dictionary attack with leetspeak and suffix mutation rules
cryptokit hash crack "5f4dcc3b5aa765d61d8327deb882cf99" -w rockyou.txt --rules

# Merkle-Damgård hash length extension attack
cryptokit hash extend -a md5 -h "2be3753... " -m "user=guest" -k 16 --append "&admin=true"
```

---

## 🛠 Adding a New Attack

Adding a new attack to `cryptokit` is straightforward thanks to the modular `Attack` ABC:

1. Create a new file in `cryptokit/` (or in `cryptokit/rsa/attacks/`):
```python
from typing import Any
from cryptokit.base import Attack, Candidate
from cryptokit.scoring import score

class MyCustomAttack(Attack):
    name = "my_custom_attack"

    def applicable(self, **ctx: Any) -> bool:
        """Return True if required parameters exist in the context."""
        return "ciphertext" in ctx

    def run(self, ciphertext: bytes, **ctx: Any) -> list[Candidate]:
        """Execute the attack and return a list of Candidates."""
        # 1. Perform mathematical cryptanalysis
        recovered_pt = b"flag{custom_attack_success}"

        # 2. Return Candidate scored against flag patterns and English
        return [
            Candidate(
                plaintext=recovered_pt,
                method=self.name,
                params={"custom_param": 42},
                score=score(recovered_pt),
            )
        ]
```

2. Register the attack class in `cryptokit/rsa/runner.py` (if RSA) or `cryptokit/auto.py`.
3. Add a test with known test vectors in `tests/test_my_custom_attack.py`.

---

## 🧪 Running Tests

```bash
# Run the entire test suite
pytest -v

# Run only RSA tests
pytest tests/test_rsa.py -v

# Run end-to-end challenge evaluation suite
python examples/run_all.py
```

---

## 📜 Educational Use Only
This toolkit is developed exclusively for legitimate Capture The Flag (CTF) security competitions and educational cryptanalysis research.
