"""Tests for cryptokit.encodings and multi-layer peeling."""

import base64
import gzip
import zlib
from cryptokit.encodings import Decoder, peel


def test_individual_codecs():
    msg = b"cryptokit_flag{test_codec_123}"
    text_msg = msg.decode()

    # Base64
    b64 = base64.b64encode(msg)
    assert Decoder.b64(b64) == msg

    # Hex
    hx = msg.hex().encode()
    assert Decoder.hex(hx) == msg

    # Base32
    b32 = base64.b32encode(msg)
    assert Decoder.b32(b32) == msg

    # Base85
    b85 = base64.b85encode(msg)
    assert Decoder.b85(b85) == msg

    # Base58
    from cryptokit.encodings import B58_ALPHABET
    b58_encoded = b"19v1nJk"
    assert len(Decoder.b58(b58_encoded)) > 0

    # Binary
    bin_str = " ".join(f"{b:08b}" for b in msg).encode()
    assert Decoder.binary(bin_str) == msg

    # Decimal
    dec_str = " ".join(str(b) for b in msg).encode()
    assert Decoder.decimal(dec_str) == msg

    # Octal
    oct_str = " ".join(oct(b)[2:] for b in msg).encode()
    assert Decoder.octal(oct_str) == msg

    # ROT13
    import codecs
    rot13_str = codecs.encode(text_msg, "rot_13").encode()
    assert Decoder.rot13(rot13_str) == msg

    # ROT47
    from cryptokit.encodings import decode_rot47
    r47 = decode_rot47(text_msg)
    assert decode_rot47(r47.decode()) == msg

    # Morse
    morse_test = b".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
    assert Decoder.morse(morse_test) == b"HELLO WORLD"

    # Bacon
    bacon_test = b"BAABB AABAA BAABA BAABB"  # TEST
    assert Decoder.bacon(bacon_test) == b"TEST"

    # HTML
    html_test = b"&lt;flag&gt; &amp; fun"
    assert Decoder.html_entities(html_test) == b"<flag> & fun"

    # Unicode escape
    uni_test = rb"\u0066\u006c\u0061\u0067"
    assert Decoder.unicode_escape(uni_test) == b"flag"

    # Reversed
    rev_test = b"}321_galf{galf"
    assert Decoder.reversed_text(rev_test) == b"flag{flag_123}"

    # Zlib / Gzip
    zl = zlib.compress(msg)
    assert Decoder.zlib_decomp(zl) == msg
    gz = gzip.compress(msg)
    assert Decoder.gzip_decomp(gz) == msg


def test_peel_multi_layer():
    # Construct a 3-layer encoded payload:
    # flag -> zlib -> base64 -> hex
    flag = b"flag{layer_by_layer_we_uncover_secrets}"
    layer1 = zlib.compress(flag)
    layer2 = base64.b64encode(layer1)
    layer3 = layer2.hex().encode("utf-8")

    candidates = peel(layer3, max_depth=5)
    assert len(candidates) > 0

    best = candidates[0]
    assert best.plaintext == flag
    assert "hex" in best.method
    assert "base64" in best.method
    assert "zlib" in best.method
