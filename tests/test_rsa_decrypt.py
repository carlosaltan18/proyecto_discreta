import unittest

from rsa_decrypt import decrypt
from rsa_encrypt import encrypt
from rsa_math import ValidationError


KEY = (367, 373, 17)


class DecryptionTests(unittest.TestCase):
    def test_reference_from_assignment(self) -> None:
        result = decrypt("026054 123875", 3, *KEY)
        self.assertEqual(result.private_exponent, 8009)
        self.assertEqual(result.padded_message, "RSA ")
        self.assertTrue(result.filler_removed)
        self.assertEqual(result.message, "RSA")
        self.assertEqual(
            [block.plaintext_six_digits for block in result.blocks],
            ["082083", "065032"],
        )

    def test_round_trip_preserves_printable_text_and_spaces(self) -> None:
        messages = (
            "AB",
            "RSA",
            "Az09!?[]{}~\\",
            "  A  Z  ",
            " A ",
        )
        for message in messages:
            with self.subTest(message=repr(message)):
                encrypted = encrypt(message, *KEY)
                recovered = decrypt(
                    encrypted.ciphertext, encrypted.original_length, *KEY
                )
                self.assertEqual(recovered.message, message)

    def test_rejects_malformed_ciphertext(self) -> None:
        invalid_values = (
            "26054",
            "026054  123875",
            " 026054",
            "026054 ",
            "02605A",
            "026054\n123875",
            "０２６０５４",
        )
        for ciphertext in invalid_values:
            with self.subTest(ciphertext=repr(ciphertext)), self.assertRaisesRegex(
                ValidationError, "seis dígitos"
            ):
                decrypt(ciphertext, 2, *KEY)

    def test_rejects_ciphertext_out_of_range(self) -> None:
        with self.assertRaisesRegex(ValidationError, "0 ≤ c < n"):
            decrypt("999999", 2, *KEY)

    def test_rejects_inconsistent_length(self) -> None:
        for length in (-1, 0, 5, "texto"):
            with self.subTest(length=length), self.assertRaises(ValidationError):
                decrypt("026054 123875", length, *KEY)

    def test_rejects_empty_ciphertext(self) -> None:
        for length in (0, 1):
            with self.subTest(length=length), self.assertRaisesRegex(
                ValidationError, "al menos un bloque"
            ):
                decrypt("", length, *KEY)

    def test_rejects_non_decimal_integers(self) -> None:
        for bad in ("1_7", "1 7", "+", "", "１７", "1.0"):
            with self.subTest(e=bad), self.assertRaises(ValidationError):
                decrypt("026054 123875", 3, 367, 373, bad)
        for bad_length in ("1_0", "３"):
            with self.subTest(length=bad_length), self.assertRaises(ValidationError):
                decrypt("026054 123875", bad_length, *KEY)

    def test_rejects_invalid_recovered_ascii_and_missing_filler(self) -> None:
        with self.assertRaisesRegex(ValidationError, "ASCII 000"):
            decrypt("000000", 2, *KEY)

        encrypted = encrypt("AB", *KEY)
        with self.assertRaisesRegex(ValidationError, "último carácter"):
            decrypt(encrypted.ciphertext, 1, *KEY)


if __name__ == "__main__":
    unittest.main()
