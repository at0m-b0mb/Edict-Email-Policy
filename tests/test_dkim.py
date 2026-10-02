"""DKIM: the tags, and the key size read out of the key material itself.

The keys here are built by :func:`spki`, which emits a real DER
``SubjectPublicKeyInfo`` around a modulus of a chosen bit length. The modulus is
not a product of primes — it does not need to be, because nothing verifies a
signature; what is under test is that Edict walks the DER correctly and reports
the size a receiver would see.
"""

import base64
import random

import pytest

from edict.core.dkim import (
    RSA_RECOMMENDED,
    RSA_WEAK,
    decode_key,
    key_bits,
    parse_dkim,
    rsa_key_bits,
    size_verdict,
)


# --- building key material ---------------------------------------------------

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(i):
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return _tlv(0x02, b)


_RSA_OID = bytes.fromhex("06092a864886f70d010101")
_NULL = bytes.fromhex("0500")


def _modulus(bits, seed=7):
    rng = random.Random(seed)
    return rng.getrandbits(bits) | (1 << (bits - 1)) | 1


def rsa_public_key(bits, seed=7):
    """A bare PKCS#1 ``RSAPublicKey``."""
    return _tlv(0x30, _der_int(_modulus(bits, seed)) + _der_int(65537))


def spki(bits, seed=7):
    """A DER ``SubjectPublicKeyInfo`` wrapping an RSA key of *bits* bits."""
    alg = _tlv(0x30, _RSA_OID + _NULL)
    return _tlv(0x30, alg + _tlv(0x03, b"\x00" + rsa_public_key(bits, seed)))


def b64(data):
    return base64.b64encode(data).decode()


def record(bits=2048, extra="", seed=7):
    tail = f"; {extra}" if extra else ""
    return f"v=DKIM1; k=rsa{tail}; p={b64(spki(bits, seed))}"


# --- the DER reader ----------------------------------------------------------

@pytest.mark.parametrize("bits", [512, 768, 1024, 1536, 2048, 3072, 4096])
def test_the_modulus_size_is_read_back_exactly(bits):
    assert rsa_key_bits(spki(bits)) == bits


@pytest.mark.parametrize("bits", [1024, 2048])
def test_a_bare_rsa_public_key_is_also_accepted(bits):
    assert rsa_key_bits(rsa_public_key(bits)) == bits


def test_the_size_is_stable_across_different_moduli():
    assert {rsa_key_bits(spki(2048, seed)) for seed in range(6)} == {2048}


@pytest.mark.parametrize("blob", [
    b"",                              # nothing at all
    b"\x30",                          # a tag with no length
    b"\x02\x01\x01",                  # an INTEGER where a SEQUENCE must be
    b"\x30\x06\x30\x01\x00\x03\x01",  # a SEQUENCE whose BIT STRING is truncated
    b"\x30\x04\x30\x02\x05\x00",      # an algorithm field and then nothing
])
def test_malformed_der_raises_rather_than_guessing(blob):
    with pytest.raises(ValueError):
        rsa_key_bits(blob)


def test_an_absurdly_small_key_reads_back_as_its_real_size():
    # SEQUENCE { INTEGER 1 } is well-formed DER for a one-bit modulus. Reading
    # it honestly is the job; calling a one-bit key an alert is the grader's.
    assert rsa_key_bits(b"\x30\x03\x02\x01\x01") == 1


def test_a_truncated_key_raises():
    with pytest.raises(ValueError):
        rsa_key_bits(spki(2048)[:40])


# --- base64 ------------------------------------------------------------------

def test_whitespace_inside_a_key_is_tolerated():
    blob = b64(spki(1024))
    spaced = blob[:40] + "\n   " + blob[40:]
    assert decode_key(spaced) == decode_key(blob)


def test_missing_padding_is_restored():
    assert decode_key("QUJD") == decode_key("QUJD".rstrip("="))


def test_an_empty_key_is_an_error():
    with pytest.raises(ValueError):
        decode_key("   ")


def test_non_base64_is_an_error():
    with pytest.raises(ValueError):
        decode_key("!!!! not base64 !!!!")


# --- key_bits ----------------------------------------------------------------

def test_key_bits_reports_an_rsa_size():
    bits, err = key_bits("rsa", b64(spki(2048)))
    assert (bits, err) == (2048, "")


def test_key_bits_reports_why_it_failed():
    bits, err = key_bits("rsa", "not-base64!!")
    assert bits is None and "base64" in err


def test_valid_base64_that_is_not_a_key_is_reported_as_malformed():
    bits, err = key_bits("rsa", b64(b"hello there, not a key"))
    assert bits is None and "malformed" in err


def test_an_ed25519_key_is_thirty_two_bytes():
    bits, err = key_bits("ed25519", b64(bytes(range(32))))
    assert (bits, err) == (256, "")


def test_an_ed25519_key_of_the_wrong_length_is_rejected():
    bits, err = key_bits("ed25519", b64(bytes(16)))
    assert bits is None and "32 bytes" in err


def test_an_unknown_algorithm_is_not_guessed_at():
    bits, err = key_bits("elgamal", b64(spki(2048)))
    assert bits is None and "elgamal" in err


# --- the record --------------------------------------------------------------

def test_a_normal_record_yields_a_size():
    key = parse_dkim(record(2048), "sel._domainkey.example.com.")
    assert key.bits == 2048
    assert key.key_type == "rsa"
    assert key.version_ok


def test_the_selector_and_domain_come_off_the_owner():
    key = parse_dkim(record(), "s1._domainkey.mail.example.com.")
    assert key.selector == "s1"
    assert key.domain == "mail.example.com"


def test_a_multi_label_selector_survives():
    key = parse_dkim(record(), "a.b._domainkey.example.com.")
    assert key.selector == "a.b"


def test_an_owner_without_domainkey_leaves_the_selector_empty():
    key = parse_dkim(record(), "example.com.")
    assert key.selector == ""
    assert key.domain == "example.com"


def test_k_defaults_to_rsa_when_it_is_not_published():
    key = parse_dkim(f"v=DKIM1; p={b64(spki(2048))}", "s._domainkey.e.example.")
    assert key.key_type == "rsa"
    assert key.bits == 2048


def test_a_record_without_a_version_tag_still_parses():
    key = parse_dkim(f"k=rsa; p={b64(spki(1024))}", "s._domainkey.e.example.")
    assert not key.version_ok
    assert key.bits == 1024


def test_an_empty_p_is_a_revoked_key_not_a_broken_one():
    key = parse_dkim("v=DKIM1; k=rsa; p=", "s._domainkey.e.example.")
    assert key.revoked
    assert key.key_error == ""
    assert key.bits is None


def test_a_missing_p_is_a_broken_record():
    key = parse_dkim("v=DKIM1; k=rsa", "s._domainkey.e.example.")
    assert not key.revoked
    assert "no p=" in key.key_error


def test_the_testing_flag_is_read():
    key = parse_dkim(record(2048, "t=y"), "s._domainkey.e.example.")
    assert key.testing
    assert not key.strict_subdomains


def test_flags_split_on_colons():
    key = parse_dkim(record(2048, "t=y:s"), "s._domainkey.e.example.")
    assert key.flags == ["y", "s"]
    assert key.testing and key.strict_subdomains


def test_hash_algorithms_split_on_colons():
    key = parse_dkim(record(2048, "h=sha1:sha256"), "s._domainkey.e.example.")
    assert key.hashes == ["sha1", "sha256"]


def test_unknown_tags_are_kept_aside():
    key = parse_dkim(record(2048, "wiggle=1"), "s._domainkey.e.example.")
    assert key.unknown_tags == ["wiggle=1"]


# --- usable / strong ---------------------------------------------------------

def test_a_big_key_is_usable_and_strong():
    key = parse_dkim(record(RSA_RECOMMENDED), "s._domainkey.e.example.")
    assert key.usable and key.strong


def test_a_small_key_is_usable_but_not_strong():
    key = parse_dkim(record(RSA_WEAK), "s._domainkey.e.example.")
    assert key.usable and not key.strong


def test_a_testing_key_is_neither():
    key = parse_dkim(record(2048, "t=y"), "s._domainkey.e.example.")
    assert not key.usable and not key.strong


def test_a_revoked_key_is_neither():
    key = parse_dkim("v=DKIM1; k=rsa; p=", "s._domainkey.e.example.")
    assert not key.usable and not key.strong


def test_an_ed25519_key_is_strong_at_any_size():
    key = parse_dkim(f"v=DKIM1; k=ed25519; p={b64(bytes(range(32)))}",
                     "s._domainkey.e.example.")
    assert key.bits == 256
    assert key.usable and key.strong


# --- the verdict word --------------------------------------------------------

@pytest.mark.parametrize("text,word", [
    (record(2048), "2048-bit"),
    (record(1024), "1024-bit"),
    ("v=DKIM1; k=rsa; p=", "revoked"),
    ("v=DKIM1; k=rsa; p=!!!", "unreadable"),
    (f"v=DKIM1; k=ed25519; p={b64(bytes(32))}", "ed25519"),
])
def test_the_size_verdict_is_a_short_phrase(text, word):
    assert size_verdict(parse_dkim(text, "s._domainkey.e.example.")) == word
