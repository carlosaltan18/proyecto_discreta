"""Validación de C y L, y desencriptación RSA por bloques."""

import re
from dataclasses import dataclass

from rsa_math import (
    RSAParameters,
    ValidationError,
    modular_inverse,
    modular_power,
    parse_integer,
    validate_parameters,
)


@dataclass(frozen=True)
class DecryptionBlock:
    """Datos de un bloque antes y después de la desencriptación."""

    position: int
    ciphertext_six_digits: str
    numeric_ciphertext: int
    numeric_plaintext: int
    ascii_codes: tuple[int, int]
    pair: str

    @property
    def plaintext_six_digits(self) -> str:
        return f"{self.numeric_plaintext:06d}"


@dataclass(frozen=True)
class DecryptionResult:
    """Resultado y datos necesarios para explicar la desencriptación."""

    parameters: RSAParameters
    private_exponent: int
    original_length: int
    filler_removed: bool
    recovered_with_filler: str
    message: str
    blocks: tuple[DecryptionBlock, ...]


def _validate_ciphertext(ciphertext: str, modulus: int) -> list[tuple[str, int]]:
    """Valida el formato exacto de C y el rango de cada bloque."""
    if not isinstance(ciphertext, str):
        raise ValidationError("El cifrado C debe ser texto.")
    if ciphertext == "":
        return []
    if re.fullmatch(r"[0-9]{6}(?: [0-9]{6})*", ciphertext) is None:
        raise ValidationError(
            "C debe contener bloques de exactamente seis dígitos (0 a 9) "
            "separados por un único espacio."
        )

    parsed_blocks: list[tuple[str, int]] = []
    for position, text in enumerate(ciphertext.split(" "), 1):
        value = int(text)
        if value >= modulus:
            raise ValidationError(
                f"El bloque {position} de C vale {value} y debe cumplir 0 ≤ c < n = {modulus}."
            )
        parsed_blocks.append((text, value))
    return parsed_blocks


def _validate_length(length: int | str, block_count: int) -> int:
    """Comprueba que L corresponda exactamente con la cantidad de bloques."""
    original_length = parse_integer(length, "L")
    if original_length < 0:
        raise ValidationError("L debe ser un entero no negativo.")
    if block_count == 0:
        if original_length != 0:
            raise ValidationError("C vacío requiere L = 0.")
        return original_length

    valid_lengths = (2 * block_count - 1, 2 * block_count)
    if original_length not in valid_lengths:
        raise ValidationError(
            f"Con {block_count} bloque(s), L debe ser {valid_lengths[0]} o {valid_lengths[1]}."
        )
    return original_length


def decrypt(
    ciphertext: str,
    length: int | str,
    p: int | str,
    q: int | str,
    e: int | str,
) -> DecryptionResult:
    """Desencripta C, conserva espacios reales y retira solo el relleno indicado por L."""
    parameters = validate_parameters(p, q, e)
    parsed_blocks = _validate_ciphertext(ciphertext, parameters.n)
    original_length = _validate_length(length, len(parsed_blocks))
    private_exponent = modular_inverse(parameters.e, parameters.phi)

    blocks: list[DecryptionBlock] = []
    recovered_pairs: list[str] = []
    for position, (ciphertext_text, numeric_ciphertext) in enumerate(parsed_blocks, 1):
        numeric_plaintext = modular_power(
            numeric_ciphertext, private_exponent, parameters.n
        )
        plaintext_text = f"{numeric_plaintext:06d}"
        ascii_codes = (int(plaintext_text[:3]), int(plaintext_text[3:]))
        for code_index, code in enumerate(ascii_codes, 1):
            if code < 32 or code > 126:
                raise ValidationError(
                    f"El bloque {position} recuperó el código ASCII {code:03d} "
                    f"en la posición {code_index}; debe estar entre 032 y 126."
                )
        pair = chr(ascii_codes[0]) + chr(ascii_codes[1])
        recovered_pairs.append(pair)
        blocks.append(
            DecryptionBlock(
                position=position,
                ciphertext_six_digits=ciphertext_text,
                numeric_ciphertext=numeric_ciphertext,
                numeric_plaintext=numeric_plaintext,
                ascii_codes=ascii_codes,
                pair=pair,
            )
        )

    recovered_with_filler = "".join(recovered_pairs)
    filler_removed = original_length % 2 == 1
    if filler_removed:
        if not recovered_with_filler or recovered_with_filler[-1] != " ":
            raise ValidationError(
                "L es impar, pero el último carácter recuperado no es el espacio de relleno."
            )
        message = recovered_with_filler[:-1]
    else:
        message = recovered_with_filler

    if len(message) != original_length:
        raise ValidationError(
            f"El mensaje recuperado tiene longitud {len(message)}, pero L indica {original_length}."
        )

    return DecryptionResult(
        parameters=parameters,
        private_exponent=private_exponent,
        original_length=original_length,
        filler_removed=filler_removed,
        recovered_with_filler=recovered_with_filler,
        message=message,
        blocks=tuple(blocks),
    )
