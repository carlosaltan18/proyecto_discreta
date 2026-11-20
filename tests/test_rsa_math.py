import unittest

from rsa_math import (
    ValidationError,
    gcd,
    is_prime,
    modular_inverse,
    modular_power,
    modular_power_trace,
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

    def test_out_of_range_modulus_rejected_before_primality(self) -> None:
        with self.assertRaisesRegex(ValidationError, "126126 < n < 1000000"):
            validate_parameters(10**100 + 39, 373, 17)

    def test_public_exponent_above_phi_is_allowed_when_coprime(self) -> None:
        parameters = validate_parameters("367", "373", "136153")
        self.assertEqual(parameters.e, parameters.phi + 1)
        self.assertEqual(gcd(parameters.e, parameters.phi), 1)

    def test_modular_trace_follows_the_recursive_mpower2_of_class(self) -> None:
        modulus = 136891
        result, steps = modular_power_trace(82083, 17, modulus)
        self.assertEqual(result, modular_power(82083, 17, modulus))
        self.assertEqual(result, 26054)
        self.assertEqual([step.exponent for step in steps], [1, 2, 4, 8, 17])
        self.assertEqual(steps[-1].result, result)
        for step in steps:
            square = (step.sub_result * step.sub_result) % modulus
            expected = (82083 * square) % modulus if step.odd else square
            self.assertEqual(step.result, expected)
            self.assertEqual(step.sub_exponent, step.exponent // 2)
            self.assertEqual(step.odd, step.exponent % 2 == 1)
        self.assertEqual(modular_power_trace(7, 0, modulus), (1, ()))

    def test_modular_power_matches_the_naive_algorithm_of_class(self) -> None:
        for base, exponent, modulus in (
            (7, 24, 11),
            (79, 79, 100),
            (1234, 13, 3337),
            (2779, 2477, 3337),
            (5, 4, 23),
            (123456, 1000, 999983),
        ):
            expected = 1 % modulus
            for _ in range(exponent):
                expected = (expected * (base % modulus)) % modulus
            with self.subTest(base=base, exponent=exponent, modulus=modulus):
                self.assertEqual(modular_power(base, exponent, modulus), expected)

    def test_modular_power_supports_very_large_exponents(self) -> None:
        self.assertEqual(modular_power(3, 10**400, 7), 4)

    def test_class_rsa_example_with_small_primes(self) -> None:
        self.assertEqual(modular_inverse(13, 3220), 2477)
        self.assertEqual(modular_power(1234, 13, 3337), 2779)
        self.assertEqual(modular_power(2779, 2477, 3337), 1234)

if __name__ == "__main__":
    unittest.main()
