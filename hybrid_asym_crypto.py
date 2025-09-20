#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hybrid_asym_crypto.py
===============================================================================
Cifrado/descifrado **asimétrico** de archivos (cualquier tipo) con esquema
**híbrido**: RSA-OAEP(SHA-256) + AES-256-GCM.

Comportamiento de nombres y borrado:
----------------------------------------------
- Al **cifrar**:
    entrada: 'archivo.ext'    → salida: 'archivo.enc'
    tras el cifrado éxitoso: se **borra** 'archivo.ext'
- Al **descifrar**:
    entrada: 'archivo.enc'    → salida: 'archivo.ext_original' (restaurada del header)
    tras el descifrado éxitoso: se **borra** 'archivo.enc'

La cabecera del .enc incluye la **extensión original completa** (p. ej. '.pdf' o
'.tar.gz') y se **autentica** con Galois/Counter Mode (Additional Authenticated Data), de modo que no pueda alterarse
sin romper la verificación del TAG.

Formato del archivo .enc (v2)
-----------------------------
MAGIC(8)='HACv1\x00\x00' |
LEN_WRAPPED_KEY(4 BE) |
WRAPPED_KEY |
NONCE(12) |
SUFFIX_LEN(2 BE) |
SUFFIX(SUFFIX_LEN, UTF-8) |
TAG(16) |
CIPHERTEXT(...)


- MAGIC: marca que el archivo sigue este formato (útil para validaciones).
- LEN_WRAPPED_KEY + WRAPPED_KEY: clave AES-256 envuelta con RSA-OAEP.
- NONCE: vector de inicialización único de GCM (no se repite con la misma clave).
- SUFFIX_LEN + SUFFIX: extensión original del archivo (.pdf, .tar.gz, o vacío).
- TAG: etiqueta de integridad generada por GCM.
- CIPHERTEXT: datos del archivo cifrados por bloques.

"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# =========================== Constantes ===========================

MAGIC = b"HACv1\x00\x00"      # Identificador del formato
CHUNK_SIZE = 64 * 1024        # 64 KiB por bloque (streaming eficiente)
AES_KEY_LEN = 32              # 32 bytes → AES-256
GCM_NONCE_LEN = 12            # 12 bytes recomendado para GCM
GCM_TAG_LEN = 16              # 16 bytes (128 bits) de TAG
SUFFIX_LEN_SIZE = 2           # 2 bytes (BE) para longitud de la extensión original


# =============================== Estructuras modelo ============================

@dataclass
class Header:
    """
    Estructura conceptual de la cabecera del .enc v2.
    """
    wrapped_key: bytes           # Clave AES envuelta con RSA-OAEP(SHA-256)
    nonce: bytes                 # Nonce de GCM (12B)
    suffix_utf8: bytes           # Extensión original en UTF-8 (incluye el punto si existe)
    tag: Optional[bytes] = None  # TAG de GCM (16B), disponible al finalizar el cifrado


# ============================== Utilidades de I/O ==============================

def _write_exact(f: BinaryIO, data: bytes) -> None:
    """Escribe 'data' en el archivo (abstracción para claridad)."""
    f.write(data)

def _read_exact(f: BinaryIO, n: int) -> bytes:
    """Lee exactamente 'n' bytes o lanza EOFError si faltan datos."""
    data = f.read(n)
    if len(data) != n:
        raise EOFError(f"Fin de archivo inesperado mientras se leían {n} bytes")
    return data


# ========================== Generación / guardado de llaves ====================

def generate_rsa_keys(bits: int = 4096) -> tuple[bytes, bytes]:
    """
    Genera un par RSA (privada+pública) y devuelve PEM serializados (sin passphrase).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

def save_keys(out_dir: Path, bits: int = 4096) -> None:
    """Genera y guarda 'private.pem' y 'public.pem' en el directorio dado."""
    out_dir.mkdir(parents=True, exist_ok=True)
    priv_pem, pub_pem = generate_rsa_keys(bits=bits)
    (out_dir / "private.pem").write_bytes(priv_pem)
    (out_dir / "public.pem").write_bytes(pub_pem)


# ============================= RSA-OAEP (envoltura) ============================

def _rsa_wrap_key(pub_pem: bytes, aes_key: bytes) -> bytes:
    """Envuelve (cifra) la clave AES con RSA-OAEP (SHA-256)."""
    public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def _rsa_unwrap_key(priv_pem: bytes, wrapped_key: bytes) -> bytes:
    """Desenvuelve (descifra) la clave AES con RSA-OAEP (SHA-256)."""
    private_key = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ============================ AES-256-GCM (streaming) ==========================

def _build_aad(magic: bytes, len_wrapped_be: bytes, wrapped_key: bytes,
               nonce: bytes, suffix_len_be: bytes, suffix_utf8: bytes) -> bytes:
    """
    Construye los bytes AAD (Additional Authenticated Data) que GCM autenticará.
    Protegemos **toda** la cabecera lógica para evitar manipulación:
    AAD = MAGIC || LEN_WRAPPED_KEY || WRAPPED_KEY || NONCE || SUFFIX_LEN || SUFFIX
    """
    return b"".join([magic, len_wrapped_be, wrapped_key, nonce, suffix_len_be, suffix_utf8])

def _get_full_suffix(path: Path) -> str:
    """
    Obtiene la extensión original completa (p.ej. '.tar.gz' o '.pdf').
    Si el archivo no tiene extensión, devuelve ''.
    """
    suffixes = path.suffixes  # lista de todas las extensiones
    return "".join(suffixes) if suffixes else ""


def encrypt_file(in_path: Path, out_path: Path, pub_key_path: Path) -> bool:
    """
    Cifra 'in_path' → 'out_path' con RSA-OAEP + AES-256-GCM.
    - Guarda la extensión original en el header y la autentica con AAD.
    - Escribe primero a '<out_path>.part' y reemplaza atómicamente al finalizar.
    """
    # 1) Material asimétrico y simétrico
    pub_pem = pub_key_path.read_bytes()
    aes_key = os.urandom(AES_KEY_LEN)
    nonce = os.urandom(GCM_NONCE_LEN)
    wrapped_key = _rsa_wrap_key(pub_pem, aes_key)

    # 2) Extensión original completa (p.ej., '.pdf' o '.tar.gz'), en UTF-8
    orig_suffix = _get_full_suffix(in_path)              # puede ser ''
    suffix_utf8 = orig_suffix.encode("utf-8")
    suffix_len_be = len(suffix_utf8).to_bytes(SUFFIX_LEN_SIZE, "big")

    # 3) Preparar cifrador GCM y AAD
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend()).encryptor()
    len_wrapped_be = len(wrapped_key).to_bytes(4, "big")
    aad = _build_aad(MAGIC, len_wrapped_be, wrapped_key, nonce, suffix_len_be, suffix_utf8)
    encryptor.authenticate_additional_data(aad)  # Autenticamos la cabecera

    # 4) Escritura atómica
    out_path_part = out_path.with_suffix(out_path.suffix + ".part")

    try:
        with in_path.open("rb") as fin, out_path_part.open("wb") as fout:
            # 4.1 Escribir cabecera (en el mismo orden usado para AAD)
            _write_exact(fout, MAGIC)
            _write_exact(fout, len_wrapped_be)
            _write_exact(fout, wrapped_key)
            _write_exact(fout, nonce)
            _write_exact(fout, suffix_len_be)
            _write_exact(fout, suffix_utf8)

            # Reservar espacio para TAG (16B) y recordar posición
            tag_pos = fout.tell()
            _write_exact(fout, b"\x00" * GCM_TAG_LEN)

            # 4.2 Cifrado por bloques
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                if ct:
                    _write_exact(fout, ct)

            # 4.3 Finalizar y escribir TAG
            encryptor.finalize()
            tag = encryptor.tag
            fout.seek(tag_pos)
            _write_exact(fout, tag)

        # 5) Reemplazo atómico
        os.replace(out_path_part, out_path)
        return True

    except Exception:
        # Limpieza del .part si algo falla
        try:
            if out_path_part.exists():
                out_path_part.unlink()
        except Exception:
            pass
        raise


def decrypt_file(in_path: Path, out_path: Path, priv_key_path: Path) -> bool:
    """
    Descifra 'in_path' (.enc) → 'out_path' con RSA-OAEP + AES-256-GCM.
    - Lee y autentica la cabecera (incluye la extensión original como AAD).
    - Escribe primero a '<out_path>.part' y reemplaza atómicamente al finalizar.
    """
    with in_path.open("rb") as fin:
        # 1) Leer cabecera
        magic = _read_exact(fin, len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Formato inválido: MAGIC no coincide (¿archivo corrupto o incompatible?).")

        len_wrapped_be = _read_exact(fin, 4)
        len_wrapped = int.from_bytes(len_wrapped_be, "big")
        wrapped_key = _read_exact(fin, len_wrapped)

        nonce = _read_exact(fin, GCM_NONCE_LEN)

        suffix_len_be = _read_exact(fin, SUFFIX_LEN_SIZE)
        suffix_len = int.from_bytes(suffix_len_be, "big")
        if suffix_len < 0 or suffix_len > 4096:
            raise ValueError("Longitud de extensión inválida.")
        suffix_utf8 = _read_exact(fin, suffix_len)

        tag = _read_exact(fin, GCM_TAG_LEN)

        # 2) Recuperar clave AES y preparar AAD
        priv_pem = priv_key_path.read_bytes()
        aes_key = _rsa_unwrap_key(priv_pem, wrapped_key)

        aad = _build_aad(magic, len_wrapped_be, wrapped_key, nonce, suffix_len_be, suffix_utf8)
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(aad)  # Autenticamos la cabecera leída

        # 3) Escritura atómica
        out_path_part = out_path.with_suffix(out_path.suffix + ".part")
        try:
            with out_path_part.open("wb") as fout:
                # Descifrado por bloques
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    pt = decryptor.update(chunk)
                    if pt:
                        _write_exact(fout, pt)

                # Verificación de TAG (lanza si no coincide)
                decryptor.finalize()

            os.replace(out_path_part, out_path)
            return True

        except Exception:
            try:
                if out_path_part.exists():
                    out_path_part.unlink()
            except Exception:
                pass
            raise


# ==================================== CLI =====================================

def _build_parser() -> argparse.ArgumentParser:
    """
    CLI:
      - gen-keys : generar llaves RSA.
      - encrypt  : cifrar archivo. Salida = BASE + '.enc' y se borra la entrada.
      - decrypt  : descifrar .enc. Salida = BASE + (extensión original) y se borra la entrada.
    """
    p = argparse.ArgumentParser(
        prog="hybrid_asym_crypto",
        description=(
            "Cifrado/descifrado híbrido RSA-OAEP(SHA-256) + AES-256-GCM.\n"
            "Salida automática: .ext → .enc (encrypt) y .enc → .ext original (decrypt).\n"
            "La entrada siempre se elimina tras completar la operación con éxito."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # gen-keys
    sp = sub.add_parser("gen-keys", help="Genera par de llaves RSA en un directorio.")
    sp.add_argument("--out-dir", required=True, type=Path, help="Directorio destino (private.pem, public.pem).")
    sp.add_argument("--bits", type=int, default=4096, help="Tamaño RSA en bits (recomendado 4096).")

    # encrypt (sin --out)
    sp = sub.add_parser("encrypt", help="Cifra un archivo con la llave pública.")
    sp.add_argument("--in",  dest="in_path", required=True, type=Path,
                    help="Archivo de entrada a cifrar. Salida: mismo nombre base con '.enc'")
    sp.add_argument("--pub", dest="pub_key", required=True, type=Path, help="Ruta a public.pem.")

    # decrypt (sin --out)
    sp = sub.add_parser("decrypt", help="Descifra un archivo con la llave privada.")
    sp.add_argument("--in",   dest="in_path", required=True, type=Path,
                    help="Archivo .enc de entrada. Salida: mismo base + extensión original.")
    sp.add_argument("--priv", dest="priv_key", required=True, type=Path, help="Ruta a private.pem.")

    return p


def main(argv: Optional[list[str]] = None) -> int:
    """
    Punto de entrada CLI.
    - Calcula nombres de salida automáticamente.
    - Ejecuta cifrado/descifrado y **siempre** borra el archivo de entrada tras éxito.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.cmd == "gen-keys":
            save_keys(args.out_dir, bits=args.bits)
            print(f"Llaves guardadas en: {args.out_dir}")

        elif args.cmd == "encrypt":
            # 'archivo.ext' → 'archivo.enc'
            out_path = args.in_path.with_suffix(".enc")
            ok = encrypt_file(args.in_path, out_path, args.pub_key)
            if ok:
                print(f"Archivo cifrado → {out_path}")
                # Borrar SIEMPRE la entrada tras éxito
                try:
                    args.in_path.unlink()
                    print(f"Entrada eliminada: {args.in_path}")
                except Exception as e:
                    print(f"Advertencia: no se pudo eliminar la entrada: {e}")

        elif args.cmd == "decrypt":
            # Validación: debe terminar en .enc
            if args.in_path.suffix != ".enc":
                raise ValueError("El archivo a descifrar debe terminar en .enc")

            # Leer cabecera mínima para conocer la extensión original (restauración del nombre)
            with args.in_path.open("rb") as fin:
                magic = _read_exact(fin, len(MAGIC))
                if magic != MAGIC:
                    raise ValueError("Formato inválido: MAGIC no coincide.")
                len_wrapped_be = _read_exact(fin, 4)
                len_wrapped = int.from_bytes(len_wrapped_be, "big")
                _ = _read_exact(fin, len_wrapped)                    # wrapped_key (se vuelve a leer en decrypt_file)
                _ = _read_exact(fin, GCM_NONCE_LEN)                  # nonce
                suffix_len_be = _read_exact(fin, SUFFIX_LEN_SIZE)
                suffix_len = int.from_bytes(suffix_len_be, "big")
                suffix_utf8 = _read_exact(fin, suffix_len)
                suffix_str = suffix_utf8.decode("utf-8")             # p.ej. ".pdf" o ".tar.gz" o ""

            # Construir out_path con la extensión original restaurada
            out_path = args.in_path.with_suffix(suffix_str if suffix_str else "")

            ok = decrypt_file(args.in_path, out_path, args.priv_key)
            if ok:
                print(f"Archivo descifrado → {out_path}")
                # Borrar SIEMPRE la entrada .enc tras éxito
                try:
                    args.in_path.unlink()
                    print(f"Entrada eliminada: {args.in_path}")
                except Exception as e:
                    print(f"Advertencia: no se pudo eliminar la entrada: {e}")

    except Exception as e:
        parser.error(str(e))
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
