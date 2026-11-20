
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
    ciphertext_text: str
    numeric_ciphertext: int
    numeric_plaintext: int
    ascii_codes: tuple[int, int]
    pair: str

    @property
    def plaintext_six_digits(self) -> str:
        return f"{self.numeric_plaintext:06d}"


@dataclass(frozen=True)
class DecryptionResult:
    """Resultado y detalle necesarios para la desencriptación."""

    parameters: RSAParameters
    private_exponent: int
    original_length: int
    filler_removed: bool
    padded_message: str
    message: str
    blocks: tuple[DecryptionBlock, ...]


def parse_ciphertext(ciphertext: str, modulus: int) -> tuple[tuple[str, int], ...]:
    """Valida bloques de seis dígitos separados por un único espacio."""
    if not isinstance(ciphertext, str):
        raise ValidationError("El cifrado C debe ser texto.")
    if ciphertext == "":
        raise ValidationError("C debe contener al menos un bloque de seis dígitos.")

    parsed_blocks: list[tuple[str, int]] = []
    for position, text in enumerate(ciphertext.split(" "), 1):
        six_ascii_digits = len(text) == 6 and all("0" <= char <= "9" for char in text)
        if not six_ascii_digits:
            raise ValidationError(
                "C debe contener bloques de exactamente seis dígitos, separados "
                f"por un único espacio. El bloque {position} no cumple el formato."
            )

        value = int(text)
        if value >= modulus:
            raise ValidationError(
                f"El bloque {position} ({text}) debe cumplir 0 ≤ c < n ({modulus})."
            )
        parsed_blocks.append((text, value))
    return tuple(parsed_blocks)


def validate_length(length: int | str, block_count: int) -> int:
    """Comprueba que L sea coherente con la cantidad de bloques de C."""
    original_length = parse_integer(length, "L")
    if original_length < 0:
        raise ValidationError("L no puede ser negativa.")

    even_length = 2 * block_count
    odd_length = even_length - 1
    if original_length not in (even_length, odd_length):
        raise ValidationError(
            f"Con {block_count} bloque(s), L debe ser {even_length} o {odd_length}."
        )
    return original_length


def decrypt(
    ciphertext: str,
    length: int | str,
    p: int | str,
    q: int | str,
    e: int | str,
) -> DecryptionResult:
    """Desencripta C y conserva exactamente los espacios del mensaje original."""
    parameters = validate_parameters(p, q, e)
    parsed_blocks = parse_ciphertext(ciphertext, parameters.n)
    original_length = validate_length(length, len(parsed_blocks))
    private_exponent = modular_inverse(parameters.e, parameters.phi)

    blocks: list[DecryptionBlock] = []
    recovered_pairs: list[str] = []
    for position, (ciphertext_text, numeric_ciphertext) in enumerate(parsed_blocks, 1):
        numeric_plaintext = modular_power(
            numeric_ciphertext, private_exponent, parameters.n
        )
        plaintext_text = f"{numeric_plaintext:06d}"
        first_code = int(plaintext_text[:3])
        second_code = int(plaintext_text[3:])

        for code in (first_code, second_code):
            if not 32 <= code <= 126:
                raise ValidationError(
                    f"El bloque {position} recupera el código ASCII {code:03d}, "
                    "fuera del rango permitido (032 a 126)."
                )

        pair = chr(first_code) + chr(second_code)
        recovered_pairs.append(pair)
        blocks.append(
            DecryptionBlock(
                position=position,
                ciphertext_text=ciphertext_text,
                numeric_ciphertext=numeric_ciphertext,
                numeric_plaintext=numeric_plaintext,
                ascii_codes=(first_code, second_code),
                pair=pair,
            )
        )

    padded_message = "".join(recovered_pairs)
    filler_removed = original_length % 2 == 1
    if filler_removed:
        if not padded_message.endswith(" "):
            raise ValidationError(
                "L indica que se agregó relleno, pero el último carácter "
                "recuperado no es un espacio."
            )
        message = padded_message[:-1]
    else:
        message = padded_message

    if len(message) != original_length:
        raise ValidationError(
            "La longitud recuperada no coincide con L; revise C y los parámetros RSA."
        )

    return DecryptionResult(
        parameters=parameters,
        private_exponent=private_exponent,
        original_length=original_length,
        filler_removed=filler_removed,
        padded_message=padded_message,
        message=message,
        blocks=tuple(blocks),
    )
