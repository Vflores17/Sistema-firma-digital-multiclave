# src/core/hashing.py

"""
hashing.py

Funciones para calcular hashes SHA-256 de archivos, bytes y texto.

Se utiliza para garantizar la integridad de los contratos
y generar el hash del PDF antes de firmarlo.
"""

import hashlib
import pathlib


CHUNK_SIZE = 8192


def sha256_bytes(data: bytes) -> str:
    """
    Calcula el SHA256 de un bloque de bytes.

    Args:
        data (bytes): datos a hashear

    Returns:
        str: hash SHA256 en hexadecimal
    """
    sha = hashlib.sha256()
    sha.update(data)
    return sha.hexdigest()


def sha256_text(text: str) -> str:
    """
    Calcula SHA256 de texto.

    Args:
        text (str): texto a hashear

    Returns:
        str: hash SHA256 en hexadecimal
    """
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(file_path: str | pathlib.Path) -> str:
    """
    Calcula SHA256 de un archivo sin cargarlo completo en memoria.

    Args:
        file_path: ruta del archivo

    Returns:
        str: hash SHA256 en hexadecimal
    """

    path = pathlib.Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

    sha = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha.update(chunk)

    return sha.hexdigest()


def verify_file_hash(file_path: str | pathlib.Path, expected_hash: str) -> bool:
    """
    Verifica si el hash de un archivo coincide con el esperado.

    Args:
        file_path: ruta del archivo
        expected_hash: hash esperado

    Returns:
        bool: True si coincide
    """

    calculated_hash = sha256_file(file_path)

    return calculated_hash.lower() == expected_hash.lower()


def fingerprint(data: bytes) -> str:
    """
    Genera fingerprint SHA256 abreviado (primeros 16 bytes).

    Se usa para mostrar identificadores de claves o documentos.

    Args:
        data (bytes)

    Returns:
        str
    """

    return hashlib.sha256(data).hexdigest()[:32]