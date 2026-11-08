"""Comprehensive test suite for RSA attacks and runner."""

from Crypto.Util.number import getPrime
import pytest

from Crypto.PublicKey import RSA
from cryptokit.utils import bytes_to_long, crt, modinv
from cryptokit.rsa.attacks.small_e import SmallEAttack
from cryptokit.rsa.attacks.wiener import WienerAttack
from cryptokit.rsa.attacks.fermat import FermatAttack
from cryptokit.rsa.attacks.trial_division import TrialDivisionAttack
from cryptokit.rsa.attacks.common_modulus import CommonModulusAttack
from cryptokit.rsa.attacks.hastad import HastadAttack
from cryptokit.rsa.attacks.shared_prime import SharedPrimeAttack
from cryptokit.rsa.attacks.direct import DirectRSADecrypt
from cryptokit.rsa.attacks.rabin import RabinAttack
from cryptokit.rsa.runner import RSARunner, parse_rsa_params


def test_small_e_attack():
    flag = b"flag{cube_root_unpadded_rsa}"
    m = bytes_to_long(flag)
    e = 3
    # Choose n much larger than m^3 (flag is ~224 bits, m^3 is ~672 bits)
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    assert m**e < n

    c = pow(m, e, n)
    attack = SmallEAttack()
    assert attack.applicable(c=c, e=e)
    candidates = attack.run(c=c, e=e, n=n)
    assert len(candidates) > 0
    assert candidates[0].plaintext == flag


def test_fermat_attack():
    flag = b"flag{close_primes_fermat_factor}"
    m = bytes_to_long(flag)
    # Generate close primes (> 256 bits so n > m)
    p = getPrime(256)
    q = p + 18
    while True:
        from sympy import isprime
        if isprime(q):
            break
        q += 2

    n = p * q
    e = 65537
    c = pow(m, e, n)

    attack = FermatAttack()
    assert attack.applicable(n=n)
    candidates = attack.run(n=n, e=e, c=c)
    assert len(candidates) > 0
    assert candidates[0].plaintext == flag
    assert candidates[0].params["p"] in (p, q)


def test_wiener_attack():
    flag = b"flag{wiener_small_private_exponent}"
    m = bytes_to_long(flag)

    # Generate vulnerable RSA key with small d < (1/3) * n^(1/4)
    while True:
        p = getPrime(256)
        q = getPrime(256)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # Choose small d
        d = getPrime(60)
        try:
            e = modinv(d, phi)
            if e > 1:
                break
        except Exception:
            continue

    c = pow(m, e, n)
    attack = WienerAttack()
    assert attack.applicable(n=n, e=e)
    candidates = attack.run(n=n, e=e, c=c)
    assert len(candidates) > 0
    assert candidates[0].plaintext == flag
    assert candidates[0].params["d"] == d


def test_trial_division():
    flag = b"flag{small_prime_factor}"
    m = bytes_to_long(flag)
    p = 65537  # small prime
    q = getPrime(256)  # ensure n > m
    n = p * q
    e = 65539
    c = pow(m, e, n)

    attack = TrialDivisionAttack()
    candidates = attack.run(n=n, e=e, c=c)
    assert len(candidates) > 0
    assert candidates[0].plaintext == flag


def test_common_modulus():
    flag = b"flag{common_modulus_coprime_exponents}"
    m = bytes_to_long(flag)
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    e1 = 3
    e2 = 5
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)

    attack = CommonModulusAttack()
    assert attack.applicable(n=n, e1=e1, e2=e2, c1=c1, c2=c2)
    candidates = attack.run(n=n, e1=e1, e2=e2, c1=c1, c2=c2)
    assert len(candidates) > 0
    assert candidates[0].plaintext == flag


def test_hastad_broadcast():
    flag = b"flag{hastad_broadcast_crt_iroot}"
    m = bytes_to_long(flag)
    e = 3
    moduli = []
    ciphertexts = []
    for _ in range(e):
        p = getPrime(256)
        q = getPrime(256)
        ni = p * q
        moduli.append(ni)
        ciphertexts.append(pow(m, e, ni))

    attack = HastadAttack()
    assert attack.applicable(e=e, moduli=moduli, ciphertexts=ciphertexts)
    candidates = attack.run(e=e, moduli=moduli, ciphertexts=ciphertexts)
    assert len(candidates) > 0
    assert candidates[0].plaintext == flag


def test_shared_prime():
    flag1 = b"flag{shared_prime_modulus_1}"
    flag2 = b"flag{shared_prime_modulus_2}"
    m1 = bytes_to_long(flag1)
    m2 = bytes_to_long(flag2)

    p = getPrime(256)
    q1 = getPrime(256)
    q2 = getPrime(256)
    n1 = p * q1
    n2 = p * q2
    e = 65537
    c1 = pow(m1, e, n1)
    c2 = pow(m2, e, n2)

    attack = SharedPrimeAttack()
    assert attack.applicable(moduli=[n1, n2])
    candidates = attack.run(moduli=[n1, n2], ciphertexts=[c1, c2], e=e)
    assert len(candidates) >= 2
    found_flags = {c.plaintext for c in candidates}
    assert flag1 in found_flags
    assert flag2 in found_flags


def test_direct_decrypt():
    flag = b"flag{known_d_or_factors}"
    m = bytes_to_long(flag)
    p = getPrime(256)
    q = getPrime(256)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    c = pow(m, e, n)

    attack = DirectRSADecrypt()
    # Given d
    cand_d = attack.run(c=c, n=n, d=d)
    assert cand_d[0].plaintext == flag

    # Given p and q
    cand_pq = attack.run(c=c, n=n, p=p, q=q, e=e)
    assert cand_pq[0].plaintext == flag


def test_rabin():
    flag = b"flag{rabin_square_root}"
    m = bytes_to_long(flag)
    # Primes = 3 mod 4 (> 128 bits so n > m)
    while True:
        p = getPrime(128)
        if p % 4 == 3:
            break
    while True:
        q = getPrime(128)
        if q % 4 == 3 and q != p:
            break

    n = p * q
    c = pow(m, 2, n)

    attack = RabinAttack()
    assert attack.applicable(c=c, p=p, q=q)
    candidates = attack.run(c=c, p=p, q=q, n=n)
    found = any(c.plaintext == flag for c in candidates)
    assert found


def test_rsa_runner_and_parsing():
    p = getPrime(256)
    q = p + 18
    while True:
        from sympy import isprime
        if isprime(q):
            break
        q += 2
    n = p * q
    e = 65537
    flag = b"flag{rsa_runner_unified_orchestration}"
    m = bytes_to_long(flag)
    c = pow(m, e, n)

    pasted = f"""
    # RSA Challenge parameters
    n = {n}
    e = {e}
    c = {c}
    """
    params = parse_rsa_params(pasted)
    assert params["n"] == n
    assert params["e"] == e
    assert params["c"] == c

    runner = RSARunner(offline=True, attack_timeout=5.0)
    candidates, logs, pem = runner.run_all(**params)

    assert len(candidates) > 0
    assert candidates[0].plaintext == flag
    assert logs["fermat"] == "SUCCESS"
    assert pem is not None
    assert "-----BEGIN RSA PRIVATE KEY-----" in pem

def test_encrypted_pem_with_correct_passphrase():
    key = RSA.generate(1024)
    password = "test-password"

    pem = key.export_key(
        format="PEM",
        passphrase=password,
        pkcs=8,
        protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
    ).decode()

    params = parse_rsa_params(pem, passphrase=password)

    assert params["n"] == key.n
    assert params["e"] == key.e
    assert params["d"] == key.d


def test_encrypted_pem_with_wrong_passphrase():
    key = RSA.generate(1024)

    pem = key.export_key(
        format="PEM",
        passphrase="correct-password",
        pkcs=8,
        protection="PBKDF2WithHMAC-SHA1AndAES128-CBC",
    ).decode()

    with pytest.raises(ValueError, match="encrypted PEM"):
        parse_rsa_params(pem, passphrase="wrong-password")
