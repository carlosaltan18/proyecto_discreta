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

    def test_modular_trace_explains_the_same_calculation(self) -> None:
        modulus = 136891
        result, steps = modular_power_trace(82083, 17, modulus)
        self.assertEqual(result, modular_power(82083, 17, modulus))
        self.assertEqual(result, 26054)
        self.assertEqual(len(steps), 5)
        self.assertEqual(steps[0].exponent_before, 17)
        for step in steps:
            expected_result = (
                (step.result_before * step.base_before) % modulus
                if step.multiplied
                else step.result_before
            )
            self.assertEqual(step.result_after, expected_result)
            self.assertEqual(step.base_after, (step.base_before * step.base_before) % modulus)
        self.assertEqual(modular_power_trace(7, 0, modulus), (1, ()))


if __name__ == "__main__":
    unittest.main()
