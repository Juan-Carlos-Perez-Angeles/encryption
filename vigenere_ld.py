
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vigenere_ld.py
==================================
Implementación del cifrado de Vigenère para **cifrar y descifrar** mensajes de texto en usando **clave por defecto 'LD'**, tal como en los ejemplos de clase.

► Características
------------------
- Clave por defecto: ``LD`` (se puede cambiar con ``--key``).
- Manejo de mayúsculas/minúsculas: se conserva el estilo del texto de entrada.
- Se preserva el resto de caracteres (espacios, signos, números, acentos, etc.).
- Interfaz de línea de comandos y API de funciones.
- Validación de argumentos y mensajes de ayuda claros.
- Código completamente comentado y con anotaciones de tipo.

► Uso por CLI (línea de comandos)
----------------------------------
Cifrar:
    $ python vigenere_ld.py --mode encrypt --key LD "INFORMACION"
    TQQRCPLFTRY

Descifrar:
    $ python vigenere_ld.py --mode decrypt --key LD "TQQRCPLFTRY"
    INFORMACION

Con la clave del ejemplo *DATOS* del material de clase:
    $ python vigenere_ld.py -m encrypt -k DATOS "DIPLOMADO"
    GIIZGPAWC

-------------------
- El cifrado de Vigenère suma (mod 26) el valor de la letra del mensaje
  con el valor de la letra de la clave. Descifrar es restar (mod 26).
- Aquí tomamos el alfabeto A..Z (26 letras).
"""

from __future__ import annotations

import argparse
import unicodedata
from typing import Iterable

# ----------------------------- Constantes ---------------------------------

# Definimos el alfabeto de trabajo. Solo A..Z (26 letras).
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH_LEN = len(ALPHABET)


# ----------------------------- Utilidades ---------------------------------

def _shift_char(c: str, k: str, decrypt: bool = False) -> str:
    """Aplica el corrimiento Vigenère a una letra.

    Parameters
    ----------
    c : str
        Carácter del mensaje (una sola letra).
    k : str
        Carácter de la clave (una sola letra, A..Z).
    decrypt : bool, optional
        Si True, realiza la operación inversa (resta).

    Returns
    -------
    str
        Letra resultante en MAYÚSCULA (el caso final se decide fuera).
    """
    # Índices en el alfabeto (0..25). Si 'c' no es letra, se devolverá tal cual.
    ci = ALPHABET.find(c.upper())
    ki = ALPHABET.find(k.upper())

    if ci == -1:
        # No es una letra del alfabeto (espacio, puntuación, número, etc.)
        return c

    # Operación módulo 26: suma para cifrar, resta para descifrar.
    if decrypt:
        out_index = (ci - ki) % ALPH_LEN
    else:
        out_index = (ci + ki) % ALPH_LEN

    return ALPHABET[out_index]


def _cycle_key(key: str) -> Iterable[str]:
    """Genera un ciclo infinito sobre los caracteres *alfabéticos*
    de la clave en A..Z (ignora otros).

    Examples
    --------
    >>> k = _cycle_key("L-D!")
    >>> [next(k) for _ in range(5)]
    ['L', 'D', 'L', 'D', 'L']
    """
    # Filtramos solo letras A..Z en mayúscula.
    clean = [c for c in key.upper() if c in ALPHABET]
    if not clean:
        raise ValueError("La clave debe contener al menos una letra A..Z.")
    # Generador infinito
    while True:
        for c in clean:
            yield c


# ------------------------- Núcleo de Vigenère -----------------------------

def vigenere_transform(text: str, key: str = "LD", decrypt: bool = False) -> str:
    """Transforma 'text' usando Vigenère con 'key'.

    Esta función es la base tanto para cifrar como para descifrar. Conserva
    el **estilo de mayúsculas/minúsculas** del texto original y respeta
    caracteres no alfabéticos.

    Parameters
    ----------
    text : str
        Mensaje a procesar.
    key : str, optional
        Clave de Vigenère. Por defecto 'LD'.
    decrypt : bool, optional
        Si *True*, descifra; si *False*, cifra.

    Returns
    -------
    str
        Texto transformado (mismo largo que 'text').
    """

    key_gen = _cycle_key(key)

    out_chars = []
    for orig_char, norm_char in zip(text, text):
        if norm_char.upper() in ALPHABET:
            # Tomamos la siguiente letra de la clave (cíclica)
            k = next(key_gen)
            # Aplicamos corrimiento con la letra normalizada
            shifted = _shift_char(norm_char, k, decrypt=decrypt)
            # Respetamos mayúscula/minúscula del carácter original
            shifted = shifted if orig_char.isupper() else shifted.lower()
            out_chars.append(shifted)
        else:
            # No se toca (espacios, signos, números, etc.)
            out_chars.append(orig_char)

    return "".join(out_chars)


def vigenere_encrypt(plaintext: str, key: str = "LD") -> str:
    """Cifra un mensaje con Vigenère.

    Parameters
    ----------
    plaintext : str
        Texto en claro a cifrar.
    key : str, optional
        Clave de Vigenère (por defecto 'LD').

    Returns
    -------
    str
        Criptograma.
    """
    return vigenere_transform(plaintext, key=key, decrypt=False)


def vigenere_decrypt(ciphertext: str, key: str = "LD") -> str:
    """Descifra un mensaje con Vigenère.

    Parameters
    ----------
    ciphertext : str
        Texto cifrado a descifrar.
    key : str, optional
        Clave de Vigenère (por defecto 'LD').

    Returns
    -------
    str
        Texto en claro.
    """
    return vigenere_transform(ciphertext, key=key, decrypt=True)


# ---------------------------- CLI principal --------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Crea y configura el `ArgumentParser` de la herramienta CLI."""
    parser = argparse.ArgumentParser(
        prog="vigenere_ld",
        description=(
            "Cifra o descifra textos usando el cifrado de Vigenère.\n"
            "Clave por defecto: 'LD'. Conserva mayúsculas/minúsculas y "
            "no altera espacios ni signos."
        ),
        epilog=(
            "Ejemplos:\n"
            "  vigenere_ld.py --mode encrypt --key LD \"INFORMACION\"\n"
            "  vigenere_ld.py -m decrypt -k DATOS GIIZGPAWC\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "message",
        help="Mensaje a procesar (entre comillas si contiene espacios).",
    )
    parser.add_argument(
        "-m",
        "--mode",
        choices=["encrypt", "decrypt"],
        required=True,
        help="Modo de operación: encrypt (cifrar) o decrypt (descifrar).",
    )
    parser.add_argument(
        "-k",
        "--key",
        default="LD",
        help="Clave de Vigenère (por defecto: LD). Solo se usan letras A..Z.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada para la línea de comandos.

    Parameters
    ----------
    argv : list[str] | None
        Lista de argumentos. Si es None, se usan los de sys.argv.

    Returns
    -------
    int
        Código de salida del proceso (0 = OK).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.mode == "encrypt":
            result = vigenere_encrypt(args.message, key=args.key)
        else:
            result = vigenere_decrypt(args.message, key=args.key)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
