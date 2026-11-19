import unittest

from rsa_decrypt import decrypt
from rsa_encrypt import encrypt
from rsa_math import ValidationError, modular_power


KEY = (367, 373, 17)


class DecryptionTests(unittest.TestCase):
    def test_reference_example(self) -> None:
        result = decrypt("026054 123875", 3, *KEY)

        self.assertEqual(result.private_exponent, 8009)
        self.assertEqual(result.message, "RSA")
        self.assertEqual(result.recovered_with_filler, "RSA ")
        self.assertTrue(result.filler_removed)
        self.assertEqual(
            [block.plaintext_six_digits for block in result.blocks],
            ["082083", "065032"],
        )
        self.assertEqual(result.blocks[0].ciphertext_six_digits, "026054")

    def test_round_trip_preserves_supported_text_exactly(self) -> None:
        messages = (
            "AB",
            "RSA",
            "Mayusculas y minusculas 123 !@#",
            "  espacios  consecutivos  ",
            "inicio y final ",
            " impar ",
        )
        for message in messages:
            with self.subTest(message=repr(message)):
                encrypted = encrypt(message, *KEY)
                decrypted = decrypt(
                    encrypted.ciphertext, encrypted.original_length, *KEY
                )
                self.assertEqual(decrypted.message, message)

    def test_empty_message(self) -> None:
        result = decrypt("", "0", *KEY)
        self.assertEqual(result.message, "")
        self.assertEqual(result.blocks, ())
        self.assertFalse(result.filler_removed)

    def test_rejects_invalid_rsa_parameters(self) -> None:
        invalid_keys = (
            (367, 367, 17),
            (369, 373, 17),
            (3, 5, 7),
            (367, 373, 2),
        )
        for key in invalid_keys:
            with self.subTest(key=key):
                with self.assertRaises(ValidationError):
                    decrypt("", 0, *key)

    def test_rejects_malformed_ciphertext(self) -> None:
        malformed_values = (
            "26054",
            "0026054",
            "026054  123875",
            " 026054",
            "026054 ",
            "026054\t123875",
            "026054\n123875",
            "02605x",
            "１２３８７５",
        )
        for ciphertext in malformed_values:
            with self.subTest(ciphertext=repr(ciphertext)):
                with self.assertRaisesRegex(ValidationError, "seis dígitos"):
                    decrypt(ciphertext, 2, *KEY)

    def test_rejects_ciphertext_out_of_range(self) -> None:
        with self.assertRaisesRegex(ValidationError, "0 ≤ c < n"):
            decrypt("136891", 2, *KEY)

    def test_rejects_invalid_or_incompatible_length(self) -> None:
        cases = (
            ("", 1),
            ("026054", -1),
            ("026054", 0),
            ("026054", 3),
            ("026054 123875", 2),
            ("026054", "uno"),
        )
        for ciphertext, length in cases:
            with self.subTest(ciphertext=ciphertext, length=length):
                with self.assertRaises(ValidationError):
                    decrypt(ciphertext, length, *KEY)

    def test_rejects_recovered_ascii_out_of_range(self) -> None:
        invalid_plaintext = 31065  # 031 y 065
        ciphertext = modular_power(invalid_plaintext, KEY[2], KEY[0] * KEY[1])
        with self.assertRaisesRegex(ValidationError, "ASCII 031"):
            decrypt(f"{ciphertext:06d}", 2, *KEY)

    def test_rejects_odd_length_without_space_filler(self) -> None:
        encrypted = encrypt("AB", *KEY)
        with self.assertRaisesRegex(ValidationError, "espacio de relleno"):
            decrypt(encrypted.ciphertext, 1, *KEY)


if __name__ == "__main__":
    unittest.main()
