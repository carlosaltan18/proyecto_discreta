import unittest

from rsa_math import (
    ValidationError,
    gcd,
    is_prime,
    modular_inverse,
    modular_power,
    validate_parameters,
)


class MathTests(unittest.TestCase):
    def test_reference_parameters_and_algorithms(self) -> None:
        parameters = validate_parameters(367, 373, 17)
        self.assertEqual((parameters.n, parameters.phi), (136891, 136152))
        self.assertEqual(gcd(parameters.e, parameters.phi), 1)
        self.assertEqual(modular_inverse(parameters.e, parameters.phi), 8009)
        self.assertEqual(modular_power(82083, 17, parameters.n), 26054)
        self.assertEqual(modular_power(26054, 8009, parameters.n), 82083)

    def test_boundary_and_invalid_parameters(self) -> None:
        self.assertFalse(is_prime(1))
        self.assertFalse(is_prime(369))
        self.assertTrue(is_prime(373))
        for p, q, e in ((367, 367, 17), (101, 103, 17), (367, 373, 2)):
            with self.subTest(p=p, q=q, e=e), self.assertRaises(ValidationError):
                validate_parameters(p, q, e)


if __name__ == "__main__":
    unittest.main()
