# src/core/key_manager.py

"""
key_manager.py

Módulo para generar y manejar claves simétricas seguras (AES-256).

Funciones:
- generar_clave()
- clave_a_base64()
- base64_a_clave()
- fingerprint_clave()
- guardar_clave()
- cargar_clave()
"""

import os
import base64
import hashlib
import pathlib


# Tamaño de clave AES-256
KEY_BYTES = 32


def generar_clave(nbytes: int = KEY_BYTES) -> bytes:
    """
    Genera una clave criptográficamente segura.
    """
    return os.urandom(nbytes)


def clave_a_base64(clave: bytes) -> str:
    """
    Convierte la clave a formato Base64.
    """
    return base64.b64encode(clave).decode("utf-8")


def base64_a_clave(clave_b64: str) -> bytes:
    """
    Convierte Base64 nuevamente a bytes.
    """
    return base64.b64decode(clave_b64)


def fingerprint_clave(clave: bytes) -> str:
    """
    Genera la huella SHA256 de la clave.
    """
    return hashlib.sha256(clave).hexdigest()


def guardar_clave(ruta: str, clave: bytes) -> pathlib.Path:
    """
    Guarda la clave en un archivo.
    """
    ruta = pathlib.Path(ruta)

    clave_b64 = clave_a_base64(clave)

    ruta.parent.mkdir(parents=True, exist_ok=True)

    with open(ruta, "w", encoding="utf-8") as f:
        f.write(clave_b64)

    try:
        os.chmod(ruta, 0o600)
    except Exception:
        pass

    return ruta


def cargar_clave(ruta: str) -> bytes:
    """
    Carga una clave desde archivo.
    """
    ruta = pathlib.Path(ruta)

    clave_b64 = ruta.read_text(encoding="utf-8").strip()

    return base64_a_clave(clave_b64)


def obtener_o_generar_clave(ruta: str) -> bytes:
    """
    Si la clave existe la carga,
    si no existe genera una nueva.
    """
    ruta = pathlib.Path(ruta)

    if ruta.exists():
        return cargar_clave(ruta)

    clave = generar_clave()
    guardar_clave(ruta, clave)

    return clave