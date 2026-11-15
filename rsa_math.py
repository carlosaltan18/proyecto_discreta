"""Algoritmos matemáticos del proyecto RSA de MM2015.

No se emplean math.gcd, pow con módulo ni bibliotecas criptográficas.
"""

from dataclasses import dataclass


class ValidationError(ValueError):
    """Entrada que no cumple las condiciones del enunciado."""


@dataclass(frozen=True)
class RSAParameters:
    """Parámetros validados que comparten encriptación y desencriptación."""

    p: int
    q: int
    e: int
    n: int
    phi: int


def parse_integer(value: int | str, name: str) -> int:
    """Convierte valores de la interfaz a enteros con un error legible."""
    if isinstance(value, bool):
        raise ValidationError(f"{name} debe ser un número entero.")
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"Ingrese un número entero para {name}.")
    try:
        return int(value.strip())
    except ValueError as exc:
        raise ValidationError(f"{name} debe ser un número entero.") from exc


def is_prime(number: int) -> bool:
    """Comprueba primalidad por divisores hasta la raíz, sin atajos externos."""
    if number < 2:
        return False
    if number == 2:
        return True
    if number % 2 == 0:
        return False

    divisor = 3
    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor += 2
    return True


def gcd(a: int, b: int) -> int:
    """Algoritmo de Euclides para el máximo común divisor."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Devuelve (mcd, x, y) tal que a*x + b*y = mcd."""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return old_r, old_x, old_y


def modular_inverse(value: int, modulus: int) -> int:
    """Obtiene el inverso módulo phi con Euclides extendido."""
    if modulus <= 1:
        raise ValidationError("El módulo del inverso debe ser mayor que 1.")
    divisor, coefficient, _ = extended_gcd(value, modulus)
    if divisor != 1:
        raise ValidationError(f"{value} no tiene inverso módulo {modulus}.")
    return coefficient % modulus


def modular_power(base: int, exponent: int, modulus: int) -> int:
    """Exponenciación binaria con reducción de módulo en cada paso."""
    if exponent < 0:
        raise ValueError("El exponente no puede ser negativo.")
    if modulus <= 0:
        raise ValueError("El módulo debe ser positivo.")

    result = 1 % modulus
    base %= modulus
    while exponent:
        if exponent % 2:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2
    return result


def validate_parameters(
    p: int | str, q: int | str, e: int | str
) -> RSAParameters:
    """Aplica todas las condiciones de los parámetros RSA del enunciado."""
    prime_p = parse_integer(p, "p")
    prime_q = parse_integer(q, "q")
    exponent = parse_integer(e, "e")

    # El rango de n descarta de inmediato números enormes antes de probar
    # primalidad por división de prueba (que bloquearía la interfaz).
    n = prime_p * prime_q
    if not 126126 < n < 1000000:
        raise ValidationError(
            f"n = p × q = {n} debe cumplir 126126 < n < 1000000."
        )

    if not is_prime(prime_p):
        raise ValidationError("p debe ser primo.")
    if not is_prime(prime_q):
        raise ValidationError("q debe ser primo.")
    if prime_p == prime_q:
        raise ValidationError("p y q deben ser primos distintos.")

    phi = (prime_p - 1) * (prime_q - 1)
    if exponent <= 1:
        raise ValidationError("e debe ser mayor que 1.")
    divisor = gcd(exponent, phi)
    if divisor != 1:
        raise ValidationError(f"MCD(e, φ) debe ser 1; actualmente es {divisor}.")
    return RSAParameters(prime_p, prime_q, exponent, n, phi)
