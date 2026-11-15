"""Cookie Consent Bitfield: encode and decode IAB TCF consent strings.

This package exposes a small, dependency-free bitfield codec for the
IAB Transparency and Consent Framework core consent string.  The public
surface is intentionally tiny: :class:`ConsentBitfield` plus the
:func:`encode` and :func:`decode` helpers.
"""

from .core import ConsentBitfield, ConsentError, decode, encode

__all__ = ["ConsentBitfield", "ConsentError", "decode", "encode"]
