# py-cookie-consent-bitfield

Encode and decode IAB TCF v2 core consent strings as structured Python objects.

```python
from py_cookie_consent_bitfield import ConsentBitfield, decode, encode

field = ConsentBitfield(
    created=1234567890,
    updated=1234567891,
    vendor_list_version=7,
    vendor_consent={1, 3, 5},
    vendor_legitimate_interest={2},
    publisher_restrictions="abc",
)

encoded = encode(field)          # unpadded base64url string
restored = decode(encoded)

assert restored.vendor_consent == {1, 3, 5}
assert restored.vendor_legitimate_interest == {2}
assert restored.publisher_restrictions == "abc"
```

## Why this exists

The IAB TCF core consent string is a bit-packed structure.  Most
implementations either pull in a large dependency or parse only the
first few fields.  This library keeps the whole core string in one small
module with no third-party dependencies.

The trade-off: we do not parse the publisher-restrictions grammar.  That
grammar is a nested, self-describing structure, and parsing it correctly
would roughly double the size of the library.  Instead we treat the
restrictions as an opaque ASCII string and round-trip it losslessly.  If
you need the structure, split the string yourself; the bitfield will
preserve whatever you put in.

## The awkward edge

Vendor IDs are stored as a dense range starting at 1.  A consent string
with a single consent for vendor 65535 therefore carries 65535 bits of
zeros before the one.  That is what the format requires, but it means
``max(vendor_consent)`` determines the encoded length.  If you build a
field with ``vendor_consent={1}`` and later add ``{65535}``, the encoded
string grows by roughly 16 KiB.  Nothing here can avoid that; it is a
property of the format.

The language field is also stricter than the spec prose: we accept only
two lowercase ASCII letters, because that is what the six-bits-per-letter
encoding can represent without ambiguity.  Mixed-case tags such as
``en-GB`` are rejected at construction time.

## API

- ``ConsentBitfield`` - dataclass holding ``version``, ``created``,
  ``updated``, ``cmf_version``, ``consent_language``,
  ``vendor_list_version``, ``vendor_consent``,
  ``vendor_legitimate_interest``, and ``publisher_restrictions``.
- ``ConsentBitfield.encode()`` - return the unpadded base64url string.
- ``ConsentBitfield.decode(encoded)`` - class method, parse a string.
- ``ConsentBitfield.to_bits()`` / ``from_bits(bits)`` - raw binary form.
- ``ConsentBitfield.to_bytes()`` / ``from_bytes(data)`` - packed bytes.
- ``encode(field)`` and ``decode(encoded)`` - module-level helpers.
- ``ConsentError`` - raised for malformed input or out-of-range fields.

All timestamps are deciseconds since the Unix epoch, stored as integers.
