"""Bitfield codec for IAB TCF v2 core consent strings.

The TCF core string is a sequence of bits packed into octets and then
base64url-encoded.  This module implements the subset of the v2 layout
that is stable and well-documented: version, created/updated timestamps,
CMF version, consent language, vendor-list version, the two consent
bitfields (vendor consent and legitimate-interest), and the publisher
restrictions string.

Design notes
------------

* We work on a plain ``int`` bit buffer rather than a bytearray.  The
  bit order in TCF is big-endian per field and the buffer grows from the
  least-significant bit, so shifting an integer is simpler and less
  error-prone than tracking bit offsets inside bytes.  The integer is
  converted to bytes only at the very end.

* ``decode`` accepts both padded and unpadded base64url.  Real-world
  strings are usually unpadded, but some emitters pad, and rejecting the
  padded form would be needlessly strict.

* The encoder always emits unpadded base64url, which is what the spec
  requires and what every CMP produces.

* Timestamps are stored as 36-bit deciseconds since the Unix epoch.  We
  expose them as ``int`` deciseconds rather than ``datetime`` because
  the conversion is lossy for sub-second precision and callers who care
  can convert themselves.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

__all__ = ["ConsentBitfield", "ConsentError", "decode", "encode"]


class ConsentError(ValueError):
    """Raised when a consent string is malformed or cannot be encoded."""


# Field widths, in bits, from the TCF v2 core string specification.
_VERSION_BITS = 6
_CREATED_BITS = 36
_UPDATED_BITS = 36
_CMF_VERSION_BITS = 12
_LANGUAGE_BITS = 12
_VENDOR_LIST_VERSION_BITS = 12
_NUM_VENDORS_BITS = 16
_NUM_RESTRICTIONS_BITS = 12
_MAX_VENDOR_ID = (1 << _NUM_VENDORS_BITS) - 1
_MAX_RESTRICTIONS = (1 << _NUM_RESTRICTIONS_BITS) - 1


def _encode_int(value: int, width: int) -> str:
    """Return *value* as *width* binary digits, most-significant first."""
    if value < 0 or value >= (1 << width):
        raise ConsentError(
            "value %d does not fit in %d bits" % (value, width)
        )
    return format(value, "0%db" % width)


def _bits_to_bytes(bits: str) -> bytes:
    """Pack a bit string (MSB first) into bytes, zero-padding on the right."""
    pad = (-len(bits)) % 8
    bits = bits + "0" * pad
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def _bytes_to_bits(data: bytes) -> str:
    """Unpack bytes into a bit string, MSB first."""
    return "".join(format(byte, "08b") for byte in data)


def _read_int(bits: str, offset: int, width: int) -> int:
    chunk = bits[offset : offset + width]
    if len(chunk) < width:
        raise ConsentError("consent string ended before field was complete")
    return int(chunk, 2)


def _encode_language(language: str) -> int:
    """Encode a two-letter language tag as six bits per character."""
    if len(language) != 2:
        raise ConsentError("language must be a two-letter tag")
    value = 0
    for char in language:
        code = ord(char)
        if code < ord("a") or code > ord("z"):
            raise ConsentError("language must be lowercase ASCII letters")
        value = (value << 6) | (code - ord("a") + 1)
    return value


def _decode_language(value: int) -> str:
    chars = []
    for shift in (6, 0):
        code = (value >> shift) & 0x3F
        if code < 1 or code > 26:
            raise ConsentError("language field contains invalid character code")
        chars.append(chr(ord("a") + code - 1))
    return "".join(chars)


@dataclass
class ConsentBitfield:
    """Structured representation of an IAB TCF v2 core consent string.

    ``vendor_consent`` and ``vendor_legitimate_interest`` are sets of
    vendor IDs.  The TCF bitfield stores them as a dense range starting
    at vendor 1, so we keep them as sets here and materialise the range
    only when encoding.

    ``publisher_restrictions`` is the raw restriction string, kept as a
    string because the TCF grammar for it is a nested structure that we
    deliberately do not parse.  Callers who need the structure can split
    it themselves; the bitfield round-trip is lossless either way.
    """

    version: int = 2
    created: int = 0
    updated: int = 0
    cmf_version: int = 2
    consent_language: str = "en"
    vendor_list_version: int = 0
    vendor_consent: set = field(default_factory=set)
    vendor_legitimate_interest: set = field(default_factory=set)
    publisher_restrictions: str = ""

    def __post_init__(self) -> None:
        self.vendor_consent = set(self.vendor_consent)
        self.vendor_legitimate_interest = set(self.vendor_legitimate_interest)
        self._validate()

    def _validate(self) -> None:
        if self.version < 0 or self.version >= (1 << _VERSION_BITS):
            raise ConsentError("version does not fit in %d bits" % _VERSION_BITS)
        if self.created < 0 or self.created >= (1 << _CREATED_BITS):
            raise ConsentError("created timestamp does not fit in 36 bits")
        if self.updated < 0 or self.updated >= (1 << _UPDATED_BITS):
            raise ConsentError("updated timestamp does not fit in 36 bits")
        if self.cmf_version < 0 or self.cmf_version >= (1 << _CMF_VERSION_BITS):
            raise ConsentError("cmf_version does not fit in 12 bits")
        if self.vendor_list_version < 0 or self.vendor_list_version >= (
            1 << _VENDOR_LIST_VERSION_BITS
        ):
            raise ConsentError("vendor_list_version does not fit in 12 bits")
        _encode_language(self.consent_language)
        for vendor_id in self.vendor_consent | self.vendor_legitimate_interest:
            if not isinstance(vendor_id, int) or vendor_id < 1 or vendor_id > _MAX_VENDOR_ID:
                raise ConsentError(
                    "vendor id %r is outside the range 1..%d" % (vendor_id, _MAX_VENDOR_ID)
                )
        if len(self.publisher_restrictions) > _MAX_RESTRICTIONS:
            raise ConsentError(
                "publisher_restrictions exceeds %d characters" % _MAX_RESTRICTIONS
            )
        if any(ord(ch) > 0x7F for ch in self.publisher_restrictions):
            raise ConsentError("publisher_restrictions must be ASCII")

    def _max_vendor(self) -> int:
        return max(
            max(self.vendor_consent, default=0),
            max(self.vendor_legitimate_interest, default=0),
        )

    def to_bits(self) -> str:
        """Return the binary representation, most-significant bit first."""
        max_vendor = self._max_vendor()
        parts: List[str] = [
            _encode_int(self.version, _VERSION_BITS),
            _encode_int(self.created, _CREATED_BITS),
            _encode_int(self.updated, _UPDATED_BITS),
            _encode_int(self.cmf_version, _CMF_VERSION_BITS),
            _encode_int(_encode_language(self.consent_language), _LANGUAGE_BITS),
            _encode_int(self.vendor_list_version, _VENDOR_LIST_VERSION_BITS),
            _encode_int(max_vendor, _NUM_VENDORS_BITS),
        ]
        for vendor_id in range(1, max_vendor + 1):
            parts.append("1" if vendor_id in self.vendor_consent else "0")
        for vendor_id in range(1, max_vendor + 1):
            parts.append("1" if vendor_id in self.vendor_legitimate_interest else "0")
        parts.append(_encode_int(len(self.publisher_restrictions), _NUM_RESTRICTIONS_BITS))
        for char in self.publisher_restrictions:
            parts.append(format(ord(char), "08b"))
        return "".join(parts)

    def to_bytes(self) -> bytes:
        """Return the packed byte representation of the consent string."""
        return _bits_to_bytes(self.to_bits())

    def encode(self) -> str:
        """Return the unpadded base64url consent string."""
        return base64.urlsafe_b64encode(self.to_bytes()).rstrip(b"=").decode("ascii")

    @classmethod
    def from_bits(cls, bits: str) -> "ConsentBitfield":
        """Parse a binary string (MSB first) into a :class:`ConsentBitfield`."""
        offset = 0

        def take(width: int) -> int:
            nonlocal offset
            value = _read_int(bits, offset, width)
            offset += width
            return value

        version = take(_VERSION_BITS)
        created = take(_CREATED_BITS)
        updated = take(_UPDATED_BITS)
        cmf_version = take(_CMF_VERSION_BITS)
        language = _decode_language(take(_LANGUAGE_BITS))
        vendor_list_version = take(_VENDOR_LIST_VERSION_BITS)
        max_vendor = take(_NUM_VENDORS_BITS)

        vendor_consent = set()
        for vendor_id in range(1, max_vendor + 1):
            if take(1):
                vendor_consent.add(vendor_id)

        vendor_legitimate_interest = set()
        for vendor_id in range(1, max_vendor + 1):
            if take(1):
                vendor_legitimate_interest.add(vendor_id)

        restriction_length = take(_NUM_RESTRICTIONS_BITS)
        restriction_chars = []
        for _ in range(restriction_length):
            restriction_chars.append(chr(take(8)))

        return cls(
            version=version,
            created=created,
            updated=updated,
            cmf_version=cmf_version,
            consent_language=language,
            vendor_list_version=vendor_list_version,
            vendor_consent=vendor_consent,
            vendor_legitimate_interest=vendor_legitimate_interest,
            publisher_restrictions="".join(restriction_chars),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "ConsentBitfield":
        """Parse packed bytes into a :class:`ConsentBitfield`."""
        return cls.from_bits(_bytes_to_bits(data))

    @classmethod
    def decode(cls, encoded: str) -> "ConsentBitfield":
        """Parse a base64url consent string into a :class:`ConsentBitfield`.

        Both padded and unpadded input are accepted; the padding is
        normalised away before decoding because ``urlsafe_b64decode``
        rejects the unpadded form unless we add the padding ourselves.
        """
        if not isinstance(encoded, str):
            raise ConsentError("consent string must be a str")
        stripped = encoded.strip()
        if not stripped:
            raise ConsentError("consent string is empty")
        unpadded = stripped.rstrip("=")
        padding = "=" * (-len(unpadded) % 4)
        try:
            raw = base64.urlsafe_b64decode(unpadded + padding)
        except (binascii.Error, ValueError) as exc:
            raise ConsentError("consent string is not valid base64url") from exc
        return cls.from_bytes(raw)


def encode(field: ConsentBitfield) -> str:
    """Convenience wrapper around :meth:`ConsentBitfield.encode`."""
    if not isinstance(field, ConsentBitfield):
        raise ConsentError("encode expects a ConsentBitfield")
    return field.encode()


def decode(encoded: str) -> ConsentBitfield:
    """Convenience wrapper around :meth:`ConsentBitfield.decode`."""
    return ConsentBitfield.decode(encoded)
