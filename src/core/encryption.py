# src/core/encryption.py

"""
encryption.py

Cifrado autenticado de archivos usando AES-256-GCM (32 bytes).
Formato .enc con:
- MAGIC + VERSION
- nombre original
- huella SHA-256 de la clave
- nonce
- ciphertext (incluye tag GCM)
- (opcional) metadatos extra (ej: contract_id, pdf_sha256) para AAD

Este módulo NO tiene GUI; está pensado para ser llamado desde Streamlit (views)
o desde scripts de core/tests.
"""

from __future__ import annotations

import os
import base64
import hashlib
import pathlib
import struct
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------- CONFIG ----------------
MAGIC = b"ULACITENC"      # 8 bytes
VERSION = 1               # 1 byte
NONCE_BYTES = 12          # recomendado para GCM
KEY_BYTES = 32            # AES-256
KEY_FPR_BYTES = 32        # SHA-256 digest bytes
EXT_PROTEGIDO = ".enc"
# ---------------------------------------


class EncryptedFileError(ValueError):
    """Errores relacionados al formato .enc o a la clave."""


def _key_fingerprint_sha256(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()


def _validate_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("La clave debe ser bytes.")
    if len(key) != KEY_BYTES:
        raise ValueError("La clave debe tener 32 bytes (AES-256).")


def _build_aad(nombre_original: str, contract_id: Optional[str], pdf_sha256_hex: Optional[str]) -> bytes:
    """
    AAD (Additional Authenticated Data): no se cifra, pero se autentica.
    Si alguien cambia nombre/contract_id/pdf_sha256, el decrypt falla.
    """
    parts = [f"name={nombre_original}"]
    if contract_id:
        parts.append(f"contract_id={contract_id}")
    if pdf_sha256_hex:
        parts.append(f"pdf_sha256={pdf_sha256_hex}")
    return ("|".join(parts)).encode("utf-8")


def _pack_blob(
    nombre_original: str,
    key_fpr: bytes,
    nonce: bytes,
    ct: bytes,
    contract_id: Optional[str] = None,
    pdf_sha256_hex: Optional[str] = None,
) -> bytes:
    """
    Formato binario:
    MAGIC (8) + VERSION (1)
    + name_len (2) + name (N)
    + key_fpr (32)
    + meta_len (2) + meta_json (M)   [meta es utf-8 simple tipo 'k=v|k=v']
    + nonce (12)
    + ciphertext (resto)

    Nota: meta no es secreto; si la cambian, el decrypt fallará gracias al AAD.
    """
    name_bytes = nombre_original.encode("utf-8")
    if len(key_fpr) != KEY_FPR_BYTES:
        raise EncryptedFileError("Huella de clave inválida.")
    if len(nonce) != NONCE_BYTES:
        raise EncryptedFileError("Nonce inválido.")

    # meta (simple, estable, sin json para evitar dependencias)
    meta_parts = []
    if contract_id:
        meta_parts.append(f"contract_id={contract_id}")
    if pdf_sha256_hex:
        meta_parts.append(f"pdf_sha256={pdf_sha256_hex}")
    meta_str = "|".join(meta_parts)
    meta_bytes = meta_str.encode("utf-8")

    if len(meta_bytes) > 65535:
        raise EncryptedFileError("Metadatos demasiado largos.")

    return (
        MAGIC
        + bytes([VERSION])
        + struct.pack(">H", len(name_bytes))
        + name_bytes
        + key_fpr
        + struct.pack(">H", len(meta_bytes))
        + meta_bytes
        + nonce
        + ct
    )


def _unpack_blob(blob: bytes) -> Tuple[str, bytes, str, bytes, bytes]:
    """
    Devuelve:
    (nombre_original, key_fpr_guardada, meta_str, nonce, ciphertext)
    """
    min_len = len(MAGIC) + 1 + 2 + KEY_FPR_BYTES + 2 + NONCE_BYTES + 16
    # 16 bytes mínimo por tag GCM (ciphertext incluye tag)
    if len(blob) < min_len:
        raise EncryptedFileError("Archivo protegido corrupto o incompleto.")

    if not blob.startswith(MAGIC):
        raise EncryptedFileError("Formato no reconocido (MAGIC inválido).")

    idx = len(MAGIC)
    ver = blob[idx]
    idx += 1
    if ver != VERSION:
        raise EncryptedFileError("Versión no soportada.")

    name_len = struct.unpack(">H", blob[idx:idx + 2])[0]
    idx += 2

    if len(blob) < idx + name_len + KEY_FPR_BYTES + 2 + NONCE_BYTES + 16:
        raise EncryptedFileError("Archivo protegido corrupto (longitudes inconsistentes).")

    nombre_original = blob[idx:idx + name_len].decode("utf-8")
    idx += name_len

    key_fpr = blob[idx:idx + KEY_FPR_BYTES]
    idx += KEY_FPR_BYTES

    meta_len = struct.unpack(">H", blob[idx:idx + 2])[0]
    idx += 2
    if len(blob) < idx + meta_len + NONCE_BYTES + 16:
        raise EncryptedFileError("Archivo protegido corrupto (metadatos inconsistentes).")

    meta_str = blob[idx:idx + meta_len].decode("utf-8")
    idx += meta_len

    nonce = blob[idx:idx + NONCE_BYTES]
    idx += NONCE_BYTES

    ct = blob[idx:]
    return nombre_original, key_fpr, meta_str, nonce, ct


def parse_meta(meta_str: str) -> dict:
    """
    Parsea el meta 'k=v|k=v' en dict.
    """
    out: dict = {}
    if not meta_str:
        return out
    for part in meta_str.split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def encrypt_file(
    input_path: str | pathlib.Path,
    key: bytes,
    *,
    output_path: Optional[str | pathlib.Path] = None,
    contract_id: Optional[str] = None,
    pdf_sha256_hex: Optional[str] = None,
) -> pathlib.Path:
    """
    Cifra un archivo y genera un .enc.
    Usa AAD = name + (contract_id) + (pdf_sha256_hex) para evitar cambios.
    """
    _validate_key(key)

    in_path = pathlib.Path(input_path).resolve()
    if not in_path.exists() or not in_path.is_file():
        raise FileNotFoundError(f"No existe el archivo: {in_path}")

    data = in_path.read_bytes()
    nonce = os.urandom(NONCE_BYTES)

    aad = _build_aad(in_path.name, contract_id, pdf_sha256_hex)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, aad)

    key_fpr = _key_fingerprint_sha256(key)

    if output_path is None:
        out_path = in_path.with_suffix(in_path.suffix + EXT_PROTEGIDO)
    else:
        out_path = pathlib.Path(output_path).resolve()

    blob = _pack_blob(in_path.name, key_fpr, nonce, ct, contract_id, pdf_sha256_hex)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(blob)

    # best-effort permisos tipo POSIX
    try:
        os.chmod(out_path, 0o600)
    except Exception:
        pass

    return out_path


def decrypt_file(
    enc_path: str | pathlib.Path,
    key: bytes,
    *,
    output_dir: Optional[str | pathlib.Path] = None,
    force_filename: Optional[str] = None,
) -> pathlib.Path:
    """
    Descifra un .enc y restaura el archivo original en output_dir.
    Verifica que la clave sea correcta comparando huella guardada.
    También falla si metadatos/AAD fueron alterados.
    """
    _validate_key(key)

    p = pathlib.Path(enc_path).resolve()
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"No existe el archivo: {p}")

    blob = p.read_bytes()
    nombre_original, key_fpr_guardada, meta_str, nonce, ct = _unpack_blob(blob)

    key_fpr_user = _key_fingerprint_sha256(key)
    if key_fpr_user != key_fpr_guardada:
        raise EncryptedFileError("Clave incorrecta: no coincide la huella registrada en este .enc.")

    meta = parse_meta(meta_str)
    contract_id = meta.get("contract_id")
    pdf_sha256_hex = meta.get("pdf_sha256")

    aad = _build_aad(nombre_original, contract_id, pdf_sha256_hex)
    aesgcm = AESGCM(key)

    try:
        data = aesgcm.decrypt(nonce, ct, aad)
    except Exception as e:
        # Esto pasa si alteraron el archivo, nonce, ciphertext o AAD/meta.
        raise EncryptedFileError(f"No se pudo descifrar (archivo alterado o AAD inválido): {e}") from e

    out_dir = pathlib.Path(output_dir).resolve() if output_dir else p.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    out_name = force_filename if force_filename else nombre_original
    out_path = out_dir / out_name
    out_path.write_bytes(data)

    try:
        os.chmod(out_path, 0o600)
    except Exception:
        pass

    return out_path


def read_key_file(key_path: str | pathlib.Path) -> bytes:
    """
    Lee una clave Base64 desde un .key (32 bytes al decodificar).
    Útil si usás el key_manager para crear/guardar claves.
    """
    kp = pathlib.Path(key_path).resolve()
    txt = kp.read_text(encoding="utf-8").strip()
    try:
        key = base64.b64decode(txt, validate=True)
    except Exception as e:
        raise ValueError("La clave del archivo .key no es Base64 válida.") from e
    _validate_key(key)
    return key