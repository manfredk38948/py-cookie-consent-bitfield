import unittest

from py_cookie_consent_bitfield import (
    ConsentBitfield,
    ConsentError,
    decode,
    encode,
)


class RoundTripTests(unittest.TestCase):
    def test_round_trip_empty_vendors(self):
        original = ConsentBitfield(
            version=2,
            created=1234567890,
            updated=1234567891,
            cmf_version=2,
            consent_language="en",
            vendor_list_version=7,
            vendor_consent=set(),
            vendor_legitimate_interest=set(),
            publisher_restrictions="",
        )
        encoded = encode(original)
        restored = decode(encoded)
        self.assertEqual(restored.version, 2)
        self.assertEqual(restored.created, 1234567890)
        self.assertEqual(restored.updated, 1234567891)
        self.assertEqual(restored.cmf_version, 2)
        self.assertEqual(restored.consent_language, "en")
        self.assertEqual(restored.vendor_list_version, 7)
        self.assertEqual(restored.vendor_consent, set())
        self.assertEqual(restored.vendor_legitimate_interest, set())
        self.assertEqual(restored.publisher_restrictions, "")

    def test_round_trip_with_vendors(self):
        original = ConsentBitfield(
            created=100,
            updated=200,
            vendor_list_version=3,
            vendor_consent={1, 3, 5},
            vendor_legitimate_interest={2, 4},
            publisher_restrictions="abc",
        )
        restored = decode(encode(original))
        self.assertEqual(restored.vendor_consent, {1, 3, 5})
        self.assertEqual(restored.vendor_legitimate_interest, {2, 4})
        self.assertEqual(restored.publisher_restrictions, "abc")

    def test_round_trip_non_ascii_restrictions_rejected(self):
        with self.assertRaises(ConsentError):
            ConsentBitfield(publisher_restrictions="caf\u00e9")

    def test_round_trip_language(self):
        original = ConsentBitfield(consent_language="fr")
        restored = decode(encode(original))
        self.assertEqual(restored.consent_language, "fr")


class ValidationTests(unittest.TestCase):
    def test_vendor_id_zero_rejected(self):
        with self.assertRaises(ConsentError):
            ConsentBitfield(vendor_consent={0})

    def test_vendor_id_too_large_rejected(self):
        with self.assertRaises(ConsentError):
            ConsentBitfield(vendor_consent={1 << 16})

    def test_language_must_be_two_lowercase_letters(self):
        with self.assertRaises(ConsentError):
            ConsentBitfield(consent_language="ENG")
        with self.assertRaises(ConsentError):
            ConsentBitfield(consent_language="e")

    def test_created_timestamp_range(self):
        with self.assertRaises(ConsentError):
            ConsentBitfield(created=-1)
        with self.assertRaises(ConsentError):
            ConsentBitfield(created=1 << 36)

    def test_restrictions_length_limit(self):
        with self.assertRaises(ConsentError):
            ConsentBitfield(publisher_restrictions="a" * (1 << 12))


class DecodeErrorTests(unittest.TestCase):
    def test_empty_string(self):
        with self.assertRaises(ConsentError):
            decode("")

    def test_non_base64(self):
        with self.assertRaises(ConsentError):
            decode("not base64!")

    def test_truncated_string(self):
        valid = encode(ConsentBitfield(vendor_consent={1, 2, 3}))
        with self.assertRaises(ConsentError):
            decode(valid[:5])

    def test_padded_input_accepted(self):
        original = ConsentBitfield(
            created=42,
            updated=43,
            vendor_consent={1, 2},
        )
        unpadded = encode(original)
        padded = unpadded + "=" * (-len(unpadded) % 4)
        restored = decode(padded)
        self.assertEqual(restored.vendor_consent, {1, 2})

    def test_decode_rejects_non_string(self):
        with self.assertRaises(ConsentError):
            decode(None)


class BitLevelTests(unittest.TestCase):
    def test_to_bits_starts_with_version(self):
        field = ConsentBitfield(version=2)
        bits = field.to_bits()
        self.assertEqual(bits[:6], "000010")

    def test_from_bits_round_trip(self):
        original = ConsentBitfield(
            version=2,
            created=999,
            updated=1000,
            vendor_consent={1, 4},
            vendor_legitimate_interest={2},
            publisher_restrictions="x",
        )
        restored = ConsentBitfield.from_bits(original.to_bits())
        self.assertEqual(restored.created, 999)
        self.assertEqual(restored.vendor_consent, {1, 4})
        self.assertEqual(restored.vendor_legitimate_interest, {2})
        self.assertEqual(restored.publisher_restrictions, "x")

    def test_encode_is_unpadded(self):
        field = ConsentBitfield(vendor_consent={1})
        self.assertNotIn("=", encode(field))

    def test_decode_ignores_surrounding_whitespace(self):
        field = ConsentBitfield(vendor_consent={1, 2})
        encoded = encode(field)
        restored = decode("  " + encoded + "\n")
        self.assertEqual(restored.vendor_consent, {1, 2})


if __name__ == "__main__":
    unittest.main()
