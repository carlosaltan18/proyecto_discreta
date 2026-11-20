import unittest

from rsa_encrypt import encrypt
from rsa_math import ValidationError


KEY = (367, 373, 17)


class EncryptionTests(unittest.TestCase):
    def test_reference_from_assignment(self) -> None:
        result = encrypt("RSA", *KEY)
        self.assertEqual(result.original_length, 3)
        self.assertEqual(result.padded_message, "RSA ")
        self.assertTrue(result.filler_added)
        self.assertEqual(
            [block.plaintext_six_digits for block in result.blocks],
            ["082083", "065032"],
        )
        self.assertEqual(result.ciphertext, "026054 123875")

    def test_spaces_survive_without_stripping(self) -> None:
        result = encrypt(" A ", *KEY)
        self.assertEqual(result.original_length, 3)
        self.assertEqual(result.padded_message, " A  ")
        self.assertEqual(result.blocks[0].pair, " A")
        self.assertEqual(result.blocks[1].pair, "  ")

        even = encrypt("  Hi  ", *KEY)
        self.assertFalse(even.filler_added)
        self.assertEqual(even.padded_message, "  Hi  ")

    def test_invalid_character_is_reported(self) -> None:
        with self.assertRaisesRegex(ValidationError, "posición 2"):
            encrypt("Aá", *KEY)
        with self.assertRaisesRegex(ValidationError, "posición 2"):
            encrypt("A\n", *KEY)

    def test_ascii_boundaries_and_empty_message_rejected(self) -> None:
        boundary = encrypt(" ~", *KEY)
        self.assertEqual(boundary.blocks[0].ascii_codes, (32, 126))
        self.assertEqual(boundary.blocks[0].plaintext_six_digits, "032126")
        self.assertEqual(len(boundary.ciphertext), 6)

        with self.assertRaisesRegex(ValidationError, "no puede estar vacío"):
            encrypt("", *KEY)


if __name__ == "__main__":
    unittest.main()
