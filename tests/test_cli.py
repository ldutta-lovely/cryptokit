"""Tests for cryptokit command-line interface."""

from typer.testing import CliRunner
from cryptokit.cli import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "cryptokit" in result.stdout
    assert "auto" in result.stdout


def test_cli_caesar():
    # ROT13 of "flag{cli_test_caesar}"
    import codecs
    ct = codecs.encode("flag{cli_test_caesar}", "rot_13")
    result = runner.invoke(app, ["caesar", ct])
    assert result.exit_code == 0
    assert "flag{" in result.stdout
    assert "shift=13" in result.stdout


def test_cli_xor_single():
    from cryptokit.utils import xor_single
    ct = xor_single(b"flag{xor_cli_works}", 0x33).hex()
    result = runner.invoke(app, ["xor", "--hex", ct])
    assert result.exit_code == 0
    assert "flag{" in result.stdout
    assert "key=51" in result.stdout


def test_cli_hash_identify():
    result = runner.invoke(app, ["hash", "identify", "5d41402abc4b2a76b9719d911017c592"])
    assert result.exit_code == 0
    assert "MD5" in result.stdout


def test_cli_decode_peel():
    import base64
    msg = base64.b64encode(b"flag{cli_peeling_works}").decode()
    result = runner.invoke(app, ["decode", msg])
    assert result.exit_code == 0
    assert "flag{" in result.stdout
    assert "base64" in result.stdout


def test_cli_auto_json():
    import base64
    msg = base64.b64encode(b"flag{cli_auto_json_output}").decode()
    result = runner.invoke(app, ["auto", msg, "--json"])
    assert result.exit_code == 0
    assert "flag{cli_auto_json_output}" in result.stdout
    assert '"score"' in result.stdout

def test_cli_rsa_calculate():
    result = runner.invoke(
        app,
        ["rsa", "calculate", "--p", "4391", "--q", "6659"],
    )
    assert result.exit_code == 0
    assert "4391" in result.stdout
    assert "6659" in result.stdout
    assert "29239669" in result.stdout


def test_cli_rsa_calculate_rejects_composite():
    result = runner.invoke(
        app,
        ["rsa", "calculate", "--p", "4", "--q", "6659"],
    )
    assert result.exit_code == 1
    assert "not a prime" in result.stdout


def test_cli_rsa_calculate_rejects_equal_primes():
    result = runner.invoke(
        app,
        ["rsa", "calculate", "--p", "7", "--q", "7"],
    )
    assert result.exit_code == 1
    assert "distinct primes" in result.stdout
