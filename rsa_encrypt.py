"""Codificación ASCII por parejas y encriptación RSA del mensaje."""

from dataclasses import dataclass

from rsa_math import RSAParameters, ValidationError, modular_power, validate_parameters


@dataclass(frozen=True)
class EncryptionBlock:
    """Datos de una pareja antes y después de la encriptación."""

    position: int
    pair: str
    ascii_codes: tuple[int, int]
    numeric_plaintext: int
    numeric_ciphertext: int

    @property
    def plaintext_six_digits(self) -> str:
        return f"{self.numeric_plaintext:06d}"

    @property
    def ciphertext_six_digits(self) -> str:
        return f"{self.numeric_ciphertext:06d}"


@dataclass(frozen=True)
class EncryptionResult:
    """Información necesaria para mostrar C, L y explicar el cálculo."""

    parameters: RSAParameters
    original_message: str
    padded_message: str
    original_length: int
    filler_added: bool
    blocks: tuple[EncryptionBlock, ...]

    @property
    def ciphertext(self) -> str:
        return " ".join(block.ciphertext_six_digits for block in self.blocks)


def validate_message(message: str) -> None:
    """Acepta solo ASCII imprimible: códigos 32 a 126 inclusive."""
    if not isinstance(message, str):
        raise ValidationError("El mensaje M debe ser texto.")
    for position, char in enumerate(message, 1):
        code = ord(char)
        if code < 32 or code > 126:
            raise ValidationError(
                f"El carácter {char!r} en la posición {position} "
                "no pertenece al ASCII imprimible (032 a 126)."
            )


def encrypt(
    message: str, p: int | str, q: int | str, e: int | str
) -> EncryptionResult:
    """Encripta M; guarda L antes de agregar un único espacio de relleno."""
    parameters = validate_parameters(p, q, e)
    validate_message(message)

    original_length = len(message)
    filler_added = original_length % 2 == 1
    padded_message = message + (" " if filler_added else "")
    blocks: list[EncryptionBlock] = []

    for offset in range(0, len(padded_message), 2):
        pair = padded_message[offset : offset + 2]
        codes = (ord(pair[0]), ord(pair[1]))
        numeric_plaintext = codes[0] * 1000 + codes[1]
        numeric_ciphertext = modular_power(
            numeric_plaintext, parameters.e, parameters.n
        )
        blocks.append(
            EncryptionBlock(
                position=offset // 2 + 1,
                pair=pair,
                ascii_codes=codes,
                numeric_plaintext=numeric_plaintext,
                numeric_ciphertext=numeric_ciphertext,
            )
        )

    return EncryptionResult(
        parameters=parameters,
        original_message=message,
        padded_message=padded_message,
        original_length=original_length,
        filler_added=filler_added,
        blocks=tuple(blocks),
    )
