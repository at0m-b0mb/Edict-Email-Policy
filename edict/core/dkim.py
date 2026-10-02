"""
DKIM — the key, and how big it really is.

A DKIM record publishes a public key at ``<selector>._domainkey.<domain>`` so a
receiver can verify the signature on a message. Almost everything about the
record is a declaration you can read off the text: ``k=`` the algorithm, ``t=y``
the testing flag that tells receivers to *ignore* the signature, an empty ``p=``
the way a key is revoked without deleting the record.

One thing is not written down anywhere, and it is the thing that matters most:
the key's size. A 1024-bit RSA key is the single most common weakness in
published DKIM, because it was the default a decade ago and nothing ever
complains. So this module reads the size out of the key itself.

``p=`` is base64 of a DER ``SubjectPublicKeyInfo``, and the modulus is the first
integer inside the bit string::

    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm         AlgorithmIdentifier,
        subjectPublicKey  BIT STRING }           -- wrapping:
    RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }

That is about forty lines of DER walking, done below with the standard library
and nothing else. Some records publish the bare ``RSAPublicKey`` instead of the
wrapper, so both shapes are accepted. An ``ed25519`` key is not DER at all — it
is thirty-two raw bytes, and is reported as 256 bits.
"""

from __future__ import annotations

import base64
import binascii

from .model import DkimKey

#: Tags defined for a DKIM key record.
KNOWN_TAGS = {"v", "g", "h", "k", "n", "p", "s", "t"}

#: Key algorithms a receiver is expected to understand.
KEY_TYPES = {"rsa", "ed25519"}

#: RSA sizes, and what each one means in practice.
RSA_WEAK = 1024          # factorable by a determined adversary; still common
RSA_RECOMMENDED = 2048   # the floor every modern guide gives

FLAG_MEANING = {
    "y": ("testing", "receivers are told to treat the signature as if it were "
                     "not there"),
    "s": ("strict", "the signing domain must match the From domain exactly"),
}


# --- a very small DER reader -------------------------------------------------

def _read_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value at *i*; return ``(tag, value, next_i)``."""
    if i + 2 > len(data):
        raise ValueError("truncated before a tag")
    tag = data[i]
    first = data[i + 1]
    i += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported length form")
        if i + count > len(data):
            raise ValueError("truncated length")
        length = int.from_bytes(data[i:i + count], "big")
        i += count
    if i + length > len(data):
        raise ValueError("truncated value")
    return tag, data[i:i + length], i + length


_SEQUENCE = 0x30
_INTEGER = 0x02
_BIT_STRING = 0x03


def _modulus_bits(modulus: bytes) -> int:
    """Bit length of a DER INTEGER's bytes, ignoring the sign padding."""
    trimmed = modulus.lstrip(b"\x00")
    if not trimmed:
        raise ValueError("zero modulus")
    return (len(trimmed) - 1) * 8 + trimmed[0].bit_length()


def rsa_key_bits(der: bytes) -> int:
    """Read an RSA key's modulus size out of DER key material.

    Accepts a ``SubjectPublicKeyInfo`` (what DKIM is supposed to publish) or a
    bare ``RSAPublicKey`` (what some generators actually emit).
    """
    tag, body, _ = _read_tlv(der, 0)
    if tag != _SEQUENCE:
        raise ValueError("key material does not start with a SEQUENCE")

    # Bare RSAPublicKey: SEQUENCE { INTEGER modulus, INTEGER exponent }
    inner_tag, inner_val, _ = _read_tlv(body, 0)
    if inner_tag == _INTEGER:
        return _modulus_bits(inner_val)

    if inner_tag != _SEQUENCE:
        raise ValueError("unexpected algorithm field")

    # SubjectPublicKeyInfo: skip AlgorithmIdentifier, open the BIT STRING.
    _, _, j = _read_tlv(body, 0)
    tag, bits, _ = _read_tlv(body, j)
    if tag != _BIT_STRING:
        raise ValueError("no BIT STRING after the algorithm")
    if not bits or bits[0] != 0:
        raise ValueError("key bit string is not byte-aligned")

    tag, rsa, _ = _read_tlv(bits[1:], 0)
    if tag != _SEQUENCE:
        raise ValueError("bit string does not hold an RSAPublicKey")
    tag, modulus, _ = _read_tlv(rsa, 0)
    if tag != _INTEGER:
        raise ValueError("RSAPublicKey does not start with the modulus")
    return _modulus_bits(modulus)


def decode_key(blob: str) -> bytes:
    """Base64-decode a ``p=`` value, tolerating whitespace and missing padding."""
    cleaned = "".join(blob.split())
    if not cleaned:
        raise ValueError("empty key")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"not valid base64 ({exc})") from exc


def key_bits(key_type: str, blob: str) -> tuple[int | None, str]:
    """Size of a published key, or ``(None, reason)`` if it cannot be read."""
    try:
        raw = decode_key(blob)
    except ValueError as exc:
        return None, str(exc)

    if key_type == "ed25519":
        if len(raw) != 32:
            return None, f"an ed25519 key must be 32 bytes, this one is {len(raw)}"
        return 256, ""

    if key_type != "rsa":
        return None, f"Edict cannot read a {key_type} key"

    try:
        return rsa_key_bits(raw), ""
    except ValueError as exc:
        return None, f"the key material is malformed ({exc})"


# --- the record --------------------------------------------------------------

def _split_owner(owner: str) -> tuple[str, str]:
    """``sel._domainkey.example.com`` -> ``("sel", "example.com")``."""
    labels = [lab for lab in owner.rstrip(".").split(".") if lab]
    lowered = [lab.lower() for lab in labels]
    if "_domainkey" not in lowered:
        return "", ".".join(labels).lower()
    cut = lowered.index("_domainkey")
    return ".".join(labels[:cut]), ".".join(labels[cut + 1:]).lower()


def parse_dkim(value: str, owner: str = "") -> DkimKey:
    """Read one DKIM key record, and derive the key's size from ``p=``."""
    selector, domain = _split_owner(owner)
    key = DkimKey(owner=owner, selector=selector, domain=domain,
                  raw=value.strip())

    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            key.unknown_tags.append(part)
            continue
        name, _, val = part.partition("=")
        tag = name.strip().lower()
        if tag not in KNOWN_TAGS:
            key.unknown_tags.append(part)
            continue
        # ``p`` arrives with its base64 intact; the rest get their whitespace
        # trimmed. A repeated tag keeps the first, as a receiver would.
        key.tags.setdefault(tag, val.strip())

    # RFC 6376 recommends v=DKIM1 but a receiver must accept a record without
    # it, so a missing version is a note rather than a parse failure.
    key.version_ok = key.tags.get("v", "").lower() == "dkim1"

    if key.revoked:
        key.bits, key.key_error = None, ""
    elif "p" in key.tags:
        key.bits, key.key_error = key_bits(key.key_type, key.tags["p"])
    else:
        key.bits, key.key_error = None, "the record publishes no p= key at all"

    return key


def size_verdict(key: DkimKey) -> str:
    """A short phrase for the size of one key, for the UI and the CLI."""
    if key.revoked:
        return "revoked"
    if key.key_error:
        return "unreadable"
    if key.key_type == "ed25519":
        return "ed25519"
    if key.bits is None:
        return "unknown"
    return f"{key.bits}-bit"
