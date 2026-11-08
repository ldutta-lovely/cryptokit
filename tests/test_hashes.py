"""Tests for hash identification, cracking, and length extension."""

import hashlib
from cryptokit.hashes import identify_hash, crack_hash, hash_length_extension


def test_identify_hash():
    md5_h = hashlib.md5(b"test").hexdigest()
    assert "MD5" in identify_hash(md5_h)

    sha1_h = hashlib.sha1(b"test").hexdigest()
    assert "SHA-1" in identify_hash(sha1_h)

    sha256_h = hashlib.sha256(b"test").hexdigest()
    assert "SHA-256" in identify_hash(sha256_h)

    bcrypt_h = "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
    assert "bcrypt" in identify_hash(bcrypt_h)


def test_crack_hash():
    wordlist = ["dragon", "monkey", "secret", "admin"]

    # Simple match
    target_md5 = hashlib.md5(b"secret").hexdigest()
    res = crack_hash(target_md5, wordlist, algorithm="md5", use_rules=False)
    assert res is not None
    assert res[0] == "secret"

    # Rule match: suffix "123" on "admin"
    target_sha256 = hashlib.sha256(b"admin123").hexdigest()
    res_rule = crack_hash(target_sha256, wordlist, algorithm="sha256", use_rules=True)
    assert res_rule is not None
    assert res_rule[0] == "admin123"

    # Leetspeak match: "s3cr3t"
    target_leet = hashlib.md5(b"s3cr3t").hexdigest()
    res_leet = crack_hash(target_leet, wordlist, algorithm="md5", use_rules=True)
    assert res_leet is not None
    assert res_leet[0] == "s3cr3t"


def test_hash_length_extension_md5():
    secret_key = b"MY_SECRET_KEY_12"  # 16 bytes
    orig_msg = b"count=10&lat=37.351&user=guest"
    orig_hash = hashlib.md5(secret_key + orig_msg).hexdigest()

    append_data = b"&admin=true"
    forged_msg, forged_hash = hash_length_extension(
        "md5",
        orig_hash,
        orig_msg,
        key_length=len(secret_key),
        append_data=append_data,
    )

    # Server verification: compute md5(secret_key + forged_msg)
    expected_hash = hashlib.md5(secret_key + forged_msg).hexdigest()
    assert forged_hash == expected_hash
    assert append_data in forged_msg


def test_hash_length_extension_sha1():
    secret_key = b"VERY_SECURE_KEY"  # 15 bytes
    orig_msg = b"action=view&file=report.pdf"
    orig_hash = hashlib.sha1(secret_key + orig_msg).hexdigest()

    append_data = b"&action=download&file=/etc/passwd"
    forged_msg, forged_hash = hash_length_extension(
        "sha1",
        orig_hash,
        orig_msg,
        key_length=len(secret_key),
        append_data=append_data,
    )

    expected_hash = hashlib.sha1(secret_key + forged_msg).hexdigest()
    assert forged_hash == expected_hash
    assert append_data in forged_msg


def test_hash_length_extension_sha256():
    secret_key = b"CUSTOM_SECRET_KEY_FOR_TESTING"  # 30 bytes
    orig_msg = b"session=abc1234&auth=normal"
    orig_hash = hashlib.sha256(secret_key + orig_msg).hexdigest()

    append_data = b"&auth=administrator&flag=give_me_flag"
    forged_msg, forged_hash = hash_length_extension(
        "sha256",
        orig_hash,
        orig_msg,
        key_length=len(secret_key),
        append_data=append_data,
    )

    expected_hash = hashlib.sha256(secret_key + forged_msg).hexdigest()
    assert forged_hash == expected_hash
    assert append_data in forged_msg
